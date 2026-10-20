import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import express from 'express';
import multer from 'multer';
import yauzl from 'yauzl';

const app = express();
const PORT = Number(process.env.WORKER_PORT || 8787);
const DATA = path.resolve(process.env.WORKER_DATA_DIR || './worker-data');
const PROJECTS = path.join(DATA,'projects');
const LOGS = path.join(DATA,'logs');
const SECRETS = path.join(DATA,'secrets');
const INCOMING = path.join(DATA,'incoming');
const TOKEN = process.env.WORKER_TOKEN || '';
const MAX_UPLOAD_MB = Math.max(1,Number(process.env.WORKER_MAX_UPLOAD_MB||1024));
const MAX_ZIP_ENTRIES = Math.max(1, Number(process.env.WORKER_MAX_ZIP_ENTRIES || 100000));
const MAX_ZIP_EXPANDED_MB = Math.max(1, Number(process.env.WORKER_MAX_ZIP_EXPANDED_MB || 4096));
const MAX_ZIP_ENTRY_MB = Math.max(1, Number(process.env.WORKER_MAX_ZIP_ENTRY_MB || 2048));
const BUILD_TIMEOUT_MS = Math.max(60000, Number(process.env.WORKER_BUILD_TIMEOUT_MS || 3600000));
const GIT_TIMEOUT_MS = Math.max(60000, Number(process.env.WORKER_GIT_TIMEOUT_MS || 900000));
const VERSIONS = new Set(['3.10','3.11','3.12','3.13']);
const RUNTIME = process.env.WORKER_RUNTIME === 'docker' ? 'docker' : 'process';
const BOOT_ID = crypto.randomUUID();
fs.mkdirSync(PROJECTS,{recursive:true,mode:0o700}); fs.mkdirSync(LOGS,{recursive:true,mode:0o700}); fs.mkdirSync(SECRETS,{recursive:true,mode:0o700}); fs.mkdirSync(INCOMING,{recursive:true,mode:0o700});
if (!TOKEN || TOKEN.length < 32 || /replace-with/i.test(TOKEN)) throw new Error('WORKER_TOKEN must be a unique random value of at least 32 characters.');
if (!/^[a-f0-9]{64}$/i.test(process.env.WORKER_ENCRYPTION_KEY||'')) throw new Error('WORKER_ENCRYPTION_KEY must be 64 hex characters.');

app.disable('x-powered-by');
app.use(express.json({limit:'256kb'}));
const upload=multer({storage:multer.diskStorage({destination:(_req,_file,cb)=>cb(null,INCOMING),filename:(_req,_file,cb)=>cb(null,`${crypto.randomUUID()}.zip`)}),limits:{fileSize:MAX_UPLOAD_MB*1024*1024,files:1,fields:10,fieldSize:160000}});
const validId=(id)=>/^[a-f0-9-]{36}$/i.test(String(id||''));
const projectPath=(id)=>path.join(PROJECTS,id);
const buildLogPath=(id)=>path.join(LOGS,`${id}.build.log`);
const runtimeArchivePath=(id)=>path.join(LOGS,`${id}.runtime.log`);
const secretPath=(id)=>path.join(SECRETS,`${id}.enc`);
const safeJson=(raw)=>{try{return JSON.parse(raw)}catch{return null}};
function auth(req,res,next){
  const got=Buffer.from(String(req.get('authorization')||'').replace(/^Bearer\s+/i,''));
  const expected=Buffer.from(TOKEN);
  if(got.length!==expected.length||!crypto.timingSafeEqual(got,expected)) return res.status(401).json({error:'Worker authorization failed.'});
  next();
}
function key(){return Buffer.from(process.env.WORKER_ENCRYPTION_KEY,'hex')}
function encrypt(value){const iv=crypto.randomBytes(12);const c=crypto.createCipheriv('aes-256-gcm',key(),iv);const ct=Buffer.concat([c.update(JSON.stringify(value),'utf8'),c.final()]);return `v1.${iv.toString('base64url')}.${c.getAuthTag().toString('base64url')}.${ct.toString('base64url')}`}
function decrypt(value){const a=String(value).split('.');if(a.length!==4||a[0]!=='v1')throw new Error('Invalid encrypted worker metadata.');const d=crypto.createDecipheriv('aes-256-gcm',key(),Buffer.from(a[1],'base64url'));d.setAuthTag(Buffer.from(a[2],'base64url'));return JSON.parse(Buffer.concat([d.update(Buffer.from(a[3],'base64url')),d.final()]).toString('utf8'))}
function getSecrets(id){if(!validId(id))return {};try{return decrypt(fs.readFileSync(secretPath(id),'utf8'))}catch{return {}}}
function redact(text,secrets={}){
  let s=String(text||'');
  for(const value of Object.values(secrets)){if(typeof value==='string'&&value.length>=4)s=s.split(value).join('[REDACTED]')}
  return s.replace(/(token|password|secret|api[_-]?key)\s*([=:])\s*([^\s,;]+)/gi,'$1$2[REDACTED]')
    .replace(/(Bot\s+)[A-Za-z0-9._-]{20,}/g,'$1[REDACTED]').replace(/\x1b\[[0-9;]*m/g,'');
}
function combineDockerOutput(stdout,stderr){
  const lines=[];
  for(const [channel,value] of [['stdout',stdout],['stderr',stderr]]){
    for(const line of String(value||'').split(/\r?\n/))if(line)lines.push({line,channel,stamp:(line.match(/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\s/)||[])[1]||''});
  }
  // Docker's CLI demultiplexes stdout/stderr. Sort timestamped lines so the two
  // actual process streams are presented in chronological order where possible.
  lines.sort((a,b)=>a.stamp&&b.stamp?(a.stamp.localeCompare(b.stamp)):(a.stamp?-1:b.stamp?1:0));
  return lines.map(x=>x.line).join('\n')+(lines.length?'\n':'');
}
function allSecretValues(...maps){
  const result={};let index=0;
  for(const map of maps)for(const value of Object.values(map||{}))if(typeof value==='string'&&value.length>=4)result[`__secret_${index++}`]=value;
  return result;
}
function validateSecretsForRedaction(raw){const parsed=safeJson(raw||'{}');return parsed&&typeof parsed==='object'&&!Array.isArray(parsed)?parsed:{}}
function appendBuild(id,chunk,secrets={}){
  const safe=redact(chunk.toString(),secrets);
  fs.appendFileSync(buildLogPath(id),safe,{mode:0o600});
}
function createBuildLogWriter(id,secrets={}){
  const longest=Math.max(0,...Object.values(secrets).filter(v=>typeof v==='string').map(v=>v.length));
  const hold=Math.min(8300,Math.max(256,longest+16));const pending={out:'',err:''};
  const write=(value)=>{if(value)appendBuild(id,value,secrets)};
  return {
    push(chunk,channel='out'){const key=channel==='err'?'err':'out';const combined=pending[key]+chunk.toString();const count=Math.min(hold,combined.length);const cut=combined.length-count;write(combined.slice(0,cut));pending[key]=combined.slice(cut)},
    flush(){write(pending.out);write(pending.err);pending.out='';pending.err=''}
  };
}
async function loggedRun(id,command,args,secrets,options={}){
  const writer=createBuildLogWriter(id,secrets);
  try{return await run(command,args,{...options,onOutput:(chunk,channel)=>writer.push(chunk,channel)})}
  finally{writer.flush()}
}
function run(command,args,{cwd,env,timeout=180000,onOutput,cleanEnv=false,captureLimit=200000}={}){
  return new Promise((resolve,reject)=>{
    const inherited=cleanEnv?{PATH:process.env.PATH||'/usr/local/bin:/usr/bin:/bin',HOME:'/tmp',LANG:'C',LC_ALL:'C'}:process.env;
    const child=spawn(command,args,{cwd,env:{...inherited,...env},stdio:['ignore','pipe','pipe'],shell:false});
    let stdout='',stderr='',settled=false;
    const timer=setTimeout(()=>{child.kill('SIGTERM');setTimeout(()=>child.kill('SIGKILL'),3000).unref();},timeout);
    const collect=(dest,chunk)=>{if(onOutput){onOutput(chunk,dest);return}const text=chunk.toString();if(dest==='out')stdout=captureLimit===Infinity?stdout+text:(stdout+text).slice(-captureLimit);else stderr=captureLimit===Infinity?stderr+text:(stderr+text).slice(-captureLimit)};
    child.stdout.on('data',c=>collect('out',c));child.stderr.on('data',c=>collect('err',c));
    child.on('error',e=>{if(settled)return;settled=true;clearTimeout(timer);reject(e)});
    child.on('close',(code,signal)=>{if(settled)return;settled=true;clearTimeout(timer);if(code===0)resolve({stdout,stderr});else reject(new Error(`${command} exited with ${code===null?signal:code}: ${(stderr||stdout).trim().slice(-1500)}`))});
  });
}
function safeRepository(input){
  try{const u=new URL(input);if(u.protocol!=='https:'||u.username||u.password||u.port||u.search||u.hash)return false;const h=u.hostname.toLowerCase();if(!h||net.isIP(h)||/^[\d.]+$/.test(h)||h==='localhost'||h.endsWith('.localhost')||h.endsWith('.local')||h.endsWith('.internal')||! /^[a-z0-9.-]+$/.test(h)||h.includes('..'))return false;return true}catch{return false}
}
async function extractZip(filePath,dest){
  await fs.promises.mkdir(dest,{recursive:true,mode:0o700});
  return new Promise((resolve,reject)=>{
    yauzl.open(filePath,{lazyEntries:true,decodeStrings:true,validateEntrySizes:true,strictFileNames:true},(err,zip)=>{
      if(err)return reject(new Error('Uploaded ZIP could not be opened.'));
      let count=0,total=0,done=false;
      const fail=(message)=>{if(done)return;done=true;try{zip.close()}catch{};reject(new Error(message))};
      zip.on('error',()=>fail('Uploaded ZIP is damaged or invalid.'));
      zip.on('entry',async (entry)=>{
        if(done)return;
        try{
          const name=entry.fileName,norm=path.posix.normalize(name),mode=(entry.externalFileAttributes>>>16)&0o170000;
          if(!name||name.includes('\0')||name.includes('\\')||name.startsWith('/')||/^[a-zA-Z]:/.test(name)||name.split('/').includes('..')||norm==='..'||norm.startsWith('../'))return fail('ZIP contains an unsafe path.');
          if(mode===0o120000)return fail('ZIP symbolic links are not allowed.');
          if(++count>MAX_ZIP_ENTRIES)return fail('ZIP contains too many files for the configured extraction safety limit.');
          total+=Number(entry.uncompressedSize||0);if(total>MAX_ZIP_EXPANDED_MB*1024*1024||Number(entry.uncompressedSize||0)>MAX_ZIP_ENTRY_MB*1024*1024)return fail('ZIP expands beyond the configured extraction safety limit.');
          const target=path.resolve(dest,...name.split('/'));
          if(target!==dest&&!target.startsWith(dest+path.sep))return fail('ZIP path escaped the project directory.');
          if(name.endsWith('/')){await fs.promises.mkdir(target,{recursive:true,mode:0o700});zip.readEntry();return}
          await fs.promises.mkdir(path.dirname(target),{recursive:true,mode:0o700});
          await new Promise((res,rej)=>zip.openReadStream(entry,(e,stream)=>{if(e)return rej(e);pipeline(stream,fs.createWriteStream(target,{flags:'wx',mode:0o600})).then(res,rej)}));
          zip.readEntry();
        }catch(e){fail(e.message==='EEXIST'?'ZIP contains duplicate paths.':`Could not extract ZIP entry: ${e.message}`)}
      });
      zip.on('end',()=>{if(!done){done=true;if(!count)return reject(new Error('ZIP archive is empty.'));resolve({files:count,expandedBytes:total})}});
      zip.readEntry();
    });
  });
}
async function ensureSource(body,file,id){
  const dir=projectPath(id);
  await fs.promises.rm(dir,{recursive:true,force:true});await fs.promises.mkdir(dir,{recursive:true,mode:0o700});
  if(file){
    if(!file.originalname.toLowerCase().endsWith('.zip')||file.size<4)throw new Error('Upload a valid ZIP source archive.');
    const handle=await fs.promises.open(file.path,'r');const header=Buffer.alloc(4);
    try{await handle.read(header,0,4,0)}finally{await handle.close()}
    if(header[0]!==0x50||header[1]!==0x4b)throw new Error('Upload a valid ZIP source archive.');
    await fs.promises.chmod(file.path,0o600);await extractZip(file.path,dir);
  }else{
    const repo=String(body.repositoryUrl||'');if(!safeRepository(repo))throw new Error('Use a public HTTPS Git URL without credentials or query parameters.');
    await run('git',['-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never','clone','--depth','1','--no-recurse-submodules','--',repo,dir],{timeout:GIT_TIMEOUT_MS,cleanEnv:true,env:{GIT_TERMINAL_PROMPT:'0',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'},onOutput:(chunk)=>appendBuild(id,chunk)});
    await fs.promises.rm(path.join(dir,'.git'),{recursive:true,force:true});
  }
  // User-supplied Dockerfiles are deliberately ignored; only the generated, least-privilege runtime is built.
  await fs.promises.rm(path.join(dir,'Dockerfile'),{force:true});
  return dir;
}
function validateEnvironment(raw){
  const env=safeJson(raw||'{}');if(!env||Array.isArray(env)||typeof env!=='object')throw new Error('Invalid environment variable payload.');
  let size=0;for(const [k,v] of Object.entries(env)){if(!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(k))throw new Error(`Invalid environment variable name: ${k}`);if(typeof v!=='string'||v.includes('\n')||v.includes('\r')||v.includes('\0')||v.length>8192)throw new Error(`Invalid value for environment variable ${k}.`);size+=k.length+v.length}
  if(size>120000)throw new Error('Environment variables exceed the size limit.');return env;
}
async function archiveRuntimeBeforeReplace(id,containerName,secrets){
  let exists=false;
  try{await run('docker',['inspect','--format','{{.Id}}',containerName],{timeout:15000});exists=true}
  catch(error){if(/No such (?:object|container)|not found/i.test(error.message))return;throw error}
  if(!exists)return;
  const output=await run('docker',['logs','--timestamps','--tail','all',containerName],{timeout:Math.max(120000,Number(process.env.WORKER_LOG_HISTORY_TIMEOUT_MS||3600000)),captureLimit:Infinity});
  const stdout=combineDockerOutput(output.stdout,output.stderr);
  if(!stdout)return;
  const archive=runtimeArchivePath(id);
  const currentSize=await fs.promises.stat(archive).then(x=>x.size).catch(()=>0);
  if(currentSize){
    const handle=await fs.promises.open(archive,'r');const tail=Buffer.alloc(1);
    try{await handle.read(tail,0,1,currentSize-1)}finally{await handle.close()}
    if(tail[0]!==0x0a)await fs.promises.appendFile(archive,'\n',{mode:0o600});
  }
  await fs.promises.appendFile(archive,redact(stdout,secrets),{mode:0o600});
}
async function deployDocker(body,file){
  const id=String(body.projectId||'');if(!validId(id))throw new Error('Invalid project ID.');
  const version=String(body.pythonVersion||'3.12');if(!VERSIONS.has(version))throw new Error('Unsupported Python version.');
  const buildCommand=String(body.buildCommand||'').slice(0,500);const startCommand=String(body.startCommand||'python main.py').trim().slice(0,500);
  if(!startCommand)throw new Error('Start command is required.');
  const previousSecrets=getSecrets(id);
  const env=validateEnvironment(body.envJson);
  const dir=await ensureSource(body,file,id);
  const dockerfile=[
    `FROM python:${version}-slim`,
    'ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp PATH="/opt/venv/bin:$PATH"',
    'RUN useradd --no-create-home --uid 10001 --shell /usr/sbin/nologin bot && python -m venv /opt/venv && chown -R 10001:10001 /opt/venv',
    'WORKDIR /app',
    'COPY --chown=bot:bot . /app',
    'RUN mkdir -p /var/lib/orbithost-data && chown -R bot:bot /var/lib/orbithost-data',
    'USER 10001:10001',
    'RUN if [ -f requirements.txt ]; then /opt/venv/bin/pip install --no-cache-dir -r requirements.txt; fi',
    ...(buildCommand?[`RUN ["/bin/sh","-lc",${JSON.stringify(buildCommand)}]`]:[]),
    `CMD ["/bin/sh","-lc",${JSON.stringify(startCommand)}]`
  ].join('\n')+'\n';
  await fs.promises.writeFile(path.join(dir,'.dockerignore'),'.git\n.env\n.env.*\n*.pem\n*.key\n*.p12\n__pycache__\n*.pyc\n.venv\nvenv\nnode_modules\n',{mode:0o600});
  await fs.promises.writeFile(path.join(dir,'Dockerfile'),dockerfile,{mode:0o600});
  const log=(chunk)=>appendBuild(id,chunk,env);
  log(`\n[OrbitHost worker] Building Python ${version} image…\n`);
  const name=`orbithost-${id}`;const image=`orbithost:${id}`;const network=`orbithost-net-${id}`;
  await loggedRun(id,'docker',['build','--pull','--tag',image,'--file',path.join(dir,'Dockerfile'),dir],env,{timeout:BUILD_TIMEOUT_MS});
  log('\n[OrbitHost worker] Image built. Starting isolated bot container…\n');
  // Docker env-file avoids putting secret values in command-line arguments and process listings.
  const envFile=path.join(os.tmpdir(),`orbithost-env-${id}-${crypto.randomUUID()}`);
  try{
    const lines=Object.entries(env).map(([k,v])=>`${k}=${v}`).join('\n')+(Object.keys(env).length?'\n':'');
    await fs.promises.writeFile(envFile,lines,{mode:0o600,flag:'wx'});
    // Stop first so shutdown output is flushed before archiving the complete container history.
    try{await run('docker',['stop','--time','10',name],{timeout:20000})}catch(error){if(!/No such (?:object|container)|not found/i.test(error.message))throw error}
    await archiveRuntimeBeforeReplace(id,name,previousSecrets);
    await run('docker',['rm','--force',name],{timeout:15000}).catch(()=>{});
    await run('docker',['network','rm',network],{timeout:15000}).catch(()=>{});
    await run('docker',['network','create',network],{timeout:15000});
    const dataVolume=`orbithost-data-${id}`;
    await run('docker',['volume','create','--label',`com.orbithost.project=${id}`,dataVolume],{timeout:15000});
    const runArgs=['run','--detach','--init','--name',name,'--label',`com.orbithost.project=${id}`,'--restart','unless-stopped','--security-opt=no-new-privileges:true','--cap-drop=ALL','--user=10001:10001','--network',network,'--mount',`type=volume,src=${dataVolume},dst=/var/lib/orbithost-data`,'--env-file',envFile,'--env','PYTHONUNBUFFERED=1','--env','HOME=/tmp','--env','ORBIT_DATA_DIR=/var/lib/orbithost-data'];
    // Resource ceilings are operator-configured to match the actual worker plan. No per-user quota is applied by the control plane.
    const memory=String(process.env.WORKER_CONTAINER_MEMORY||'').trim();
    const cpus=String(process.env.WORKER_CONTAINER_CPUS||'').trim();
    const pids=String(process.env.WORKER_CONTAINER_PIDS||'').trim();
    if(memory){if(!/^[1-9]\d*(?:k|m|g|t)?i?b?$/i.test(memory))throw new Error('WORKER_CONTAINER_MEMORY must be a Docker memory value such as 512m or 2g.');runArgs.push(`--memory=${memory}`,'--memory-swap='+memory)}
    if(cpus){if(!/^\d+(?:\.\d+)?$/.test(cpus)||Number(cpus)<=0)throw new Error('WORKER_CONTAINER_CPUS must be a positive number.');runArgs.push(`--cpus=${cpus}`)}
    if(pids){if(!/^\d+$/.test(pids)||Number(pids)<16)throw new Error('WORKER_CONTAINER_PIDS must be at least 16 when configured.');runArgs.push(`--pids-limit=${pids}`)}
    runArgs.push(image);
    await fs.promises.writeFile(secretPath(id),encrypt(env),{mode:0o600});
    await loggedRun(id,'docker',runArgs,env,{timeout:60000});
  }finally{await fs.promises.rm(envFile,{force:true})}
  log('\n[OrbitHost worker] Container started. No host ports are published.\n');
  return {status:'online',containerId:name,pythonVersion:version};
}
async function dockerContainerActionDocker(id,action){
  if(!validId(id))throw new Error('Invalid project ID.');const name=`orbithost-${id}`;
  if(action==='delete'){
    const removeUnlessMissing=async(args,timeout=30000)=>{
      try{await run('docker',args,{timeout})}
      catch(error){if(!/No such (?:object|container|image|network|volume)|not found/i.test(error.message))throw error}
    };
    await removeUnlessMissing(['rm','--force',name]);
    await removeUnlessMissing(['image','rm',`orbithost:${id}`]);
    await removeUnlessMissing(['network','rm',`orbithost-net-${id}`],15000);
    await removeUnlessMissing(['volume','rm',`orbithost-data-${id}`],15000);
    await fs.promises.rm(projectPath(id),{recursive:true,force:true});await fs.promises.rm(buildLogPath(id),{force:true});await fs.promises.rm(runtimeArchivePath(id),{force:true});await fs.promises.rm(secretPath(id),{force:true});return {status:'deleted'};
  }
  if(!['start','stop','restart'].includes(action))throw new Error('Unsupported action.');
  await run('docker',[action,name],{timeout:30000});return {status:action==='stop'?'stopped':'online'};
}
async function getStatusDocker(id){
  if(!validId(id))throw new Error('Invalid project ID.');const name=`orbithost-${id}`;
  let inspect;
  try{const {stdout}=await run('docker',['inspect','--format','{{json .State}}|{{.HostConfig.Memory}}|{{.Name}}',name],{timeout:12000});inspect=stdout.trim()}catch(error){if(/No such (object|container)|not found/i.test(error.message))return {status:'stopped',cpuPercent:0,memoryMb:0,memoryLimitMb:null,uptime:0,mode:'container'};throw error}
  const [statePart,memLimit]=inspect.split('|');const state=safeJson(statePart)||{};let stats='';
  if(state.Running)try{stats=(await run('docker',['stats','--no-stream','--format','{{.CPUPerc}}|{{.MemUsage}}',name],{timeout:12000})).stdout.trim()}catch{}
  let cpu=state.Running?null:0,memory=state.Running?null:0;const [cpuText,memText]=stats.split('|');if(cpuText&&/^[-+]?\d+(?:\.\d+)?%$/.test(cpuText.trim()))cpu=Number.parseFloat(cpuText);if(memText){const m=memText.match(/([\d.]+)\s*(MiB|GiB|MB|GB|KiB|KB)/i);if(m){memory=Number(m[1]);if(/^g/i.test(m[2]))memory*=1024;else if(/^k/i.test(m[2]))memory/=1024}}
  const started=state.StartedAt&&state.StartedAt.startsWith('0001-')?null:Date.parse(state.StartedAt||'');
  const uptime=state.Running?(Number.isFinite(started)?Math.max(0,Math.floor((Date.now()-started)/1000)):null):0;
  return {status:state.Running?'online':(state.Status==='exited'?'stopped':state.Status||'stopped'),cpuPercent:cpu==null?null:Number(cpu.toFixed(1)),memoryMb:memory==null?null:Math.round(memory),memoryLimitMb:Number(memLimit)>0?Math.round(Number(memLimit)/1048576):null,uptime,mode:'container'};
}
async function getLogsDocker(id,stream){
  if(!validId(id))throw new Error('Invalid project ID.');let text='';
  let cursor=null;
  if(stream==='build'){
    text=await fs.promises.readFile(buildLogPath(id),'utf8').catch(()=> '');
    cursor=Buffer.byteLength(text,'utf8');
  } else {
    const archived=await fs.promises.readFile(runtimeArchivePath(id),'utf8').catch(()=> '');
    const current=await run('docker',['logs','--timestamps','--tail','all',`orbithost-${id}`],{timeout:Math.max(120000, Number(process.env.WORKER_LOG_HISTORY_TIMEOUT_MS || 3600000)),captureLimit:Infinity}).then(x=>combineDockerOutput(x.stdout,x.stderr)).catch(e=>/No such (?:object|container)|not found/i.test(e.message)?'':Promise.reject(e));
    text=archived&&current&&!archived.endsWith('\n')?`${archived}\n${current}`:archived+current;
  }
  const secrets=getSecrets(id);const rawLines=text.split(/\r?\n/);if(rawLines.at(-1)==='')rawLines.pop();const entries=rawLines.map((raw,i)=>{
    let message=raw,createdAt=null;
    if(stream==='runtime'){
      const stamp=raw.match(/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\s(.*)$/);
      if(stamp){createdAt=stamp[1];message=stamp[2]}
    }
    message=redact(message,secrets);
    const entryId=stream==='runtime'&&createdAt?crypto.createHash('sha256').update(`${id}\0${createdAt}\0${message}`).digest('hex'):crypto.createHash('sha256').update(`${id}\0${stream}\0${i}\0${message}`).digest('hex');
    return {id:entryId,stream,level:/error|exception|traceback|failed/i.test(message)?'error':/warn/i.test(message)?'warn':'info',message,createdAt};
  });
  if(stream==='runtime')cursor=entries.at(-1)?.createdAt||null;
  return {entries,cursor};
}
function logLevel(message){return /error|exception|traceback|failed/i.test(message)?'error':/warn/i.test(message)?'warn':'info'}
function sendLogEvent(res,stream,raw,id,secrets,cursor=null){
  let message=String(raw||'').replace(/\x1b\[[0-9;]*m/g,'');let createdAt=null;
  if(stream==='runtime'){
    const stamp=message.match(/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\s(.*)$/);
    if(stamp){createdAt=stamp[1];message=stamp[2]}
  }
  message=redact(message,secrets);
  const entryId=stream==='runtime'&&createdAt?crypto.createHash('sha256').update(`${id}\0${createdAt}\0${message}`).digest('hex'):crypto.createHash('sha256').update(`${id}\0${cursor??crypto.randomUUID()}\0${message}`).digest('hex');
  const entry={id:entryId,stream,level:logLevel(message),message,createdAt,...(cursor===null?{}:{cursor})};
  if(!res.destroyed&&!res.writableEnded)res.write(`event: log\ndata: ${JSON.stringify(entry)}\n\n`);
}
function setupSse(res){
  res.status(200).set({'Content-Type':'text/event-stream; charset=utf-8','Cache-Control':'no-cache, no-transform','Connection':'keep-alive','X-Accel-Buffering':'no'});
  res.flushHeaders();res.write(': stream connected\n\n');
}
function streamBuildLogs(req,res,id){
  const target=buildLogPath(id),secrets=getSecrets(id);
  let offset=Number(req.query.offset||0);if(!Number.isSafeInteger(offset)||offset<0)offset=0;
  let pending='',reading=false,closed=false,cursorOffset=offset;
  let decoder=new StringDecoder('utf8');
  const decodeLines=(chunk)=>{
    pending+=decoder.write(chunk);let newline;
    while((newline=pending.indexOf('\n'))>=0){
      const original=pending.slice(0,newline+1);let line=pending.slice(0,newline);if(line.endsWith('\r'))line=line.slice(0,-1);
      cursorOffset+=Buffer.byteLength(original,'utf8');pending=pending.slice(newline+1);
      sendLogEvent(res,'build',line,`${id}:${cursorOffset}`,secrets,cursorOffset);
    }
  };
  const readNewBytes=async()=>{
    if(closed||reading)return;reading=true;
    try{
      const stat=await fs.promises.stat(target).catch(()=>null);
      if(!stat)return;
      if(stat.size<offset){offset=0;cursorOffset=0;pending='';decoder=new StringDecoder('utf8');}
      if(stat.size<=offset)return;
      const stream=fs.createReadStream(target,{start:offset,end:stat.size-1});
      for await(const chunk of stream){offset+=chunk.length;decodeLines(chunk)}
    }catch{}
    finally{reading=false}
  };
  setupSse(res);
  const poll=setInterval(()=>{void readNewBytes()},250);poll.unref?.();
  const heartbeat=setInterval(()=>{if(!closed&&!res.destroyed)res.write(': keepalive\n\n')},20000);heartbeat.unref?.();
  const close=()=>{closed=true;clearInterval(poll);clearInterval(heartbeat);pending=''};
  res.on('close',close);req.on('aborted',close);
  void readNewBytes();
}
function streamRuntimeLogsDocker(req,res,id){
  const secrets=getSecrets(id);const args=['logs','--follow','--timestamps'];
  const since=String(req.query.since||'');
  if(since&& !Number.isNaN(Date.parse(since)))args.push('--since',since);else args.push('--tail','0');
  args.push(`orbithost-${id}`);
  setupSse(res);
  const child=spawn('docker',args,{shell:false,stdio:['ignore','pipe','pipe']});
  const pending={out:'',err:''};const decoders={out:new StringDecoder('utf8'),err:new StringDecoder('utf8')};let closed=false;
  const heartbeat=setInterval(()=>{if(!closed&&!res.destroyed&&!res.writableEnded)res.write(': keepalive\n\n')},15000);heartbeat.unref?.();
  const onChunk=(channel,chunk)=>{
    pending[channel]+=decoders[channel].write(chunk);
    const lines=pending[channel].split(/\r?\n/);pending[channel]=lines.pop()||'';
    for(const line of lines)if(line)sendLogEvent(res,'runtime',line,id,secrets);
  };
  child.stdout.on('data',chunk=>onChunk('out',chunk));child.stderr.on('data',chunk=>onChunk('err',chunk));
  child.on('error',(error)=>{if(!closed&&!res.destroyed)res.write(`event: stream-error\ndata: ${JSON.stringify({error:redact(error.message,secrets)})}\n\n`)});
  child.on('close',(code)=>{
    clearInterval(heartbeat);
    for(const channel of ['out','err']){pending[channel]+=decoders[channel].end();if(pending[channel]&&!closed)sendLogEvent(res,'runtime',pending[channel],id,secrets);pending[channel]=''}
    if(!closed&&!res.destroyed&&code!==0)res.write(`event: stream-error\ndata: ${JSON.stringify({error:'Docker log stream ended. Check that the bot container is running and the worker is reachable.'})}\n\n`);
    if(!res.writableEnded)res.end();
  });
  const close=()=>{closed=true;clearInterval(heartbeat);if(child.exitCode===null)child.kill('SIGTERM')};
  res.on('close',close);req.on('aborted',close);
}

// --- process runtime (WORKER_RUNTIME=process): bots run as child processes of the worker ---
const procs=new Map();
const metaPath=(id)=>path.join(SECRETS,`${id}.meta.json`);
function readMeta(id){if(!validId(id))return null;try{return safeJson(fs.readFileSync(metaPath(id),'utf8'))}catch{return null}}
function writeMeta(id,meta){fs.writeFileSync(metaPath(id),JSON.stringify(meta),{mode:0o600})}
function stampLine(text){return `${new Date().toISOString()} ${text}\n`}
function runtimeLogger(id,secrets){
  const stream=fs.createWriteStream(runtimeArchivePath(id),{flags:'a',mode:0o600});
  let pending='';const dec=new StringDecoder('utf8');
  const emit=(raw)=>{const line=raw.replace(/\r$/,'');if(line.trim())stream.write(stampLine(redact(line,secrets)))};
  return {
    write(chunk){pending+=dec.write(chunk);let i;while((i=pending.indexOf('\n'))>=0){emit(pending.slice(0,i));pending=pending.slice(i+1)}},
    line(text){stream.write(stampLine(redact(String(text),secrets)))},
    end(){pending+=dec.end();if(pending.trim())emit(pending);pending='';stream.end()}
  };
}
function childEnv(dir,userEnv,id){
  const venvBin=path.join(dir,'venv','bin');
  const base={PATH:`${venvBin}:${process.env.PATH||'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}`,HOME:'/tmp',LANG:'C.UTF-8',PYTHONUNBUFFERED:'1',ORBIT_DATA_DIR:path.join(DATA,`botdata-${id}`)};
  return {...base,...Object.fromEntries(Object.entries(userEnv||{}).filter(([k])=>!/^(WORKER_|NODE_)/.test(k)))};
}
function spawnBot(id,secrets){
  const meta=readMeta(id);
  if(!meta||!meta.startCommand)return Promise.reject(new Error('No start command recorded for this project. Deploy it first.'));
  const dir=projectPath(id);
  if(procs.has(id))return Promise.resolve({status:'online'});
  if(!fs.existsSync(dir))return Promise.reject(new Error('Project source is missing on the worker. Deploy it again.'));
  const logger=runtimeLogger(id,secrets);
  const child=spawn('/bin/sh',['-lc',meta.startCommand],{cwd:dir,env:childEnv(dir,secrets,id),stdio:['ignore','pipe','pipe'],detached:true});
  const entry={child,startedAt:Date.now(),logger,lastSample:null};
  procs.set(id,entry);
  child.stdout.on('data',c=>{try{logger.write(c)}catch{}});
  child.stderr.on('data',c=>{try{logger.write(c)}catch{}});
  child.on('close',(code,signal)=>{
    if(procs.get(id)===entry)procs.delete(id);
    try{logger.line(`[OrbitHost worker] Process exited with ${code===null?`signal ${signal}`:`exit code ${code}`}.`);logger.end()}catch{}
  });
  child.on('error',(error)=>{try{logger.line(`[OrbitHost worker] Process failed to start: ${error.message}.`);logger.end()}catch{}});
  return Promise.resolve({status:'online'});
}
function stopProcess(id,grace=10000){
  const entry=procs.get(id);if(!entry)return Promise.resolve();
  procs.delete(id);
  const child=entry.child;
  return new Promise((resolve)=>{
    let done=false;const finish=()=>{if(!done){done=true;resolve()}};
    child.once('close',finish);
    try{process.kill(-child.pid,'SIGTERM')}catch{try{child.kill('SIGTERM')}catch{}}
    const hard=setTimeout(()=>{try{process.kill(-child.pid,'SIGKILL')}catch{try{child.kill('SIGKILL')}catch{}}},Math.max(1000,grace));hard.unref?.();
    setTimeout(finish,Math.max(2000,grace+2000)).unref?.();
  });
}
async function deployProcess(body,file){
  const id=String(body.projectId||'');if(!validId(id))throw new Error('Invalid project ID.');
  const version=String(body.pythonVersion||'3.12');if(!VERSIONS.has(version))throw new Error('Unsupported Python version.');
  const buildCommand=String(body.buildCommand||'').slice(0,500);const startCommand=String(body.startCommand||'python main.py').trim().slice(0,500);
  if(!startCommand)throw new Error('Start command is required.');
  const previousSecrets=getSecrets(id);
  const env=validateEnvironment(body.envJson);
  const dir=await ensureSource(body,file,id);
  const log=(chunk)=>appendBuild(id,chunk,env);
  let hostPython='';
  try{hostPython=(await run('python3',['-c','import platform;print(platform.python_version())'],{timeout:20000})).stdout.trim()}catch{}
  log(`\n[OrbitHost worker] Process mode build. Requested Python ${version}; worker runtime Python ${hostPython||'unavailable'}.\n`);
  await fs.promises.rm(path.join(dir,'venv'),{recursive:true,force:true});
  if(fs.existsSync(path.join(dir,'requirements.txt'))){
    log('[OrbitHost worker] Creating virtual environment…\n');
    await loggedRun(id,'python3',['-m','venv',path.join(dir,'venv')],env,{cwd:dir,timeout:BUILD_TIMEOUT_MS});
    log('[OrbitHost worker] Installing requirements.txt…\n');
    await loggedRun(id,path.join(dir,'venv','bin','pip'),['install','--no-cache-dir','--no-input','-r',path.join(dir,'requirements.txt')],env,{cwd:dir,timeout:BUILD_TIMEOUT_MS});
  }
  if(buildCommand){log('[OrbitHost worker] Running build command…\n');await loggedRun(id,'/bin/sh',['-lc',buildCommand],env,{cwd:dir,timeout:BUILD_TIMEOUT_MS})}
  await stopProcess(id,10000);
  await fs.promises.writeFile(secretPath(id),encrypt(env),{mode:0o600});
  writeMeta(id,{startCommand,buildCommand,pythonVersion:version,autoStart:true});
  fs.mkdirSync(path.join(DATA,`botdata-${id}`),{recursive:true,mode:0o700});
  log('\n[OrbitHost worker] Starting process…\n');
  await spawnBot(id,env);
  log('[OrbitHost worker] Process started.\n');
  return {status:'online',containerId:`orbithost-${id}`,pythonVersion:version,runtime:'process'};
}
async function containerActionProcess(id,action){
  if(!validId(id))throw new Error('Invalid project ID.');
  const secrets=getSecrets(id);
  if(action==='delete'){
    await stopProcess(id,6000).catch(()=>{});
    procs.delete(id);
    await fs.promises.rm(projectPath(id),{recursive:true,force:true});
    await fs.promises.rm(path.join(DATA,`botdata-${id}`),{recursive:true,force:true});
    await fs.promises.rm(buildLogPath(id),{force:true});await fs.promises.rm(runtimeArchivePath(id),{force:true});await fs.promises.rm(secretPath(id),{force:true});await fs.promises.rm(metaPath(id),{force:true});
    return {status:'deleted'};
  }
  if(!['start','stop','restart'].includes(action))throw new Error('Unsupported action.');
  if(action==='stop'){await stopProcess(id);const meta=readMeta(id);if(meta)writeMeta(id,{...meta,autoStart:false});return {status:'stopped'}}
  const meta=readMeta(id);
  if(!meta||!meta.startCommand)throw new Error('No start command recorded for this project. Deploy it first.');
  if(action==='start'&&procs.has(id))return {status:'online'};
  if(action!=='start')await stopProcess(id);
  writeMeta(id,{...meta,autoStart:true});
  await spawnBot(id,secrets);
  return {status:'online'};
}
async function getStatusProcess(id){
  if(!validId(id))throw new Error('Invalid project ID.');
  const entry=procs.get(id);
  if(!entry)return {status:'stopped',cpuPercent:0,memoryMb:0,memoryLimitMb:null,uptime:0,mode:'process'};
  const pid=entry.child.pid;let cpuPercent=null,memoryMb=null;
  try{
    const stat=fs.readFileSync(`/proc/${pid}/stat`,'utf8').split(' ');
    const ticks=Number(stat[13])+Number(stat[14])+Number(stat[15])+Number(stat[16]);
    const now=Date.now();const prev=entry.lastSample;
    if(prev&&now>prev.t){const dt=(now-prev.t)/1000;cpuPercent=Math.max(0,Math.min(100*os.cpus().length,((ticks-prev.ticks)/100/dt)*100))}
    entry.lastSample={t:now,ticks};
    const rss=fs.readFileSync(`/proc/${pid}/status`,'utf8').match(/VmRSS:\s+(\d+)\s+kB/);
    if(rss)memoryMb=Math.round(Number(rss[1])/1024);
  }catch{}
  return {status:'online',cpuPercent,memoryMb,memoryLimitMb:null,uptime:Math.max(0,Math.floor((Date.now()-entry.startedAt)/1000)),mode:'process'};
}
async function getLogsProcess(id,stream){
  if(!validId(id))throw new Error('Invalid project ID.');
  let text=await fs.promises.readFile(stream==='build'?buildLogPath(id):runtimeArchivePath(id),'utf8').catch(()=> '');
  const cursor=Buffer.byteLength(text,'utf8');
  const secrets=getSecrets(id);const rawLines=text.split(/\r?\n/);if(rawLines.at(-1)==='')rawLines.pop();
  const entries=rawLines.map((raw,i)=>{
    let message=raw,createdAt=null;
    if(stream==='runtime'){const stamp=raw.match(/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\s(.*)$/);if(stamp){createdAt=stamp[1];message=stamp[2]}}
    message=redact(message,secrets);
    const entryId=stream==='runtime'&&createdAt?crypto.createHash('sha256').update(`${id}\0${createdAt}\0${message}`).digest('hex'):crypto.createHash('sha256').update(`${id}\0${stream}\0${i}\0${message}`).digest('hex');
    return {id:entryId,stream,level:/error|exception|traceback|failed/i.test(message)?'error':/warn/i.test(message)?'warn':'info',message,createdAt};
  });
  return {entries,cursor:stream==='runtime'?(entries.at(-1)?.createdAt||null):cursor};
}
function streamRuntimeLogsProcess(req,res,id){
  const secrets=getSecrets(id);const target=runtimeArchivePath(id);
  const since=String(req.query.since||'');const sinceTs=since&&!Number.isNaN(Date.parse(since))?Date.parse(since):null;
  let offset=0;
  try{
    const stat=fs.statSync(target);
    if(sinceTs){
      const data=fs.readFileSync(target,'utf8');let pos=0,found=-1;
      for(const line of data.split(/(?<=\n)/)){const m=line.match(/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)/);if(m&&Date.parse(m[1])>=sinceTs){found=pos;break}pos+=Buffer.byteLength(line,'utf8')}
      offset=found>=0?found:stat.size;
    } else offset=stat.size;
  }catch{offset=0}
  let pending='',reading=false,closed=false;
  let decoder=new StringDecoder('utf8');
  const decodeLines=(chunk)=>{
    pending+=decoder.write(chunk);let newline;
    while((newline=pending.indexOf('\n'))>=0){
      const original=pending.slice(0,newline+1);let line=pending.slice(0,newline);if(line.endsWith('\r'))line=line.slice(0,-1);
      offset+=Buffer.byteLength(original,'utf8');pending=pending.slice(newline+1);
      if(line)sendLogEvent(res,'runtime',line,id,secrets);
    }
  };
  const readNewBytes=async()=>{
    if(closed||reading)return;reading=true;
    try{
      const stat=await fs.promises.stat(target).catch(()=>null);
      if(!stat)return;
      if(stat.size<offset){offset=0;pending='';decoder=new StringDecoder('utf8')}
      if(stat.size<=offset)return;
      const stream=fs.createReadStream(target,{start:offset,end:stat.size-1});
      for await(const chunk of stream){offset+=chunk.length;decodeLines(chunk)}
    }catch{}finally{reading=false}
  };
  setupSse(res);
  const poll=setInterval(()=>{void readNewBytes()},300);poll.unref?.();
  const heartbeat=setInterval(()=>{if(!closed&&!res.destroyed)res.write(': keepalive\n\n')},15000);heartbeat.unref?.();
  const close=()=>{closed=true;clearInterval(poll);clearInterval(heartbeat);pending=''};
  res.on('close',close);req.on('aborted',close);
  void readNewBytes();
}
function recoverProcesses(){
  let files=[];try{files=fs.readdirSync(SECRETS)}catch{return}
  for(const name of files){
    const m=name.match(/^([a-f0-9-]{36})\.meta\.json$/i);if(!m)continue;
    const id=m[1];const meta=readMeta(id);
    if(!meta||meta.autoStart===false)continue;
    if(!fs.existsSync(projectPath(id)))continue;
    void spawnBot(id,getSecrets(id)).then(()=>{
      try{fs.appendFileSync(runtimeArchivePath(id),stampLine('[OrbitHost worker] Worker restarted; recorded process restarted automatically.'),{mode:0o600})}catch{}
    }).catch((error)=>{
      try{fs.appendFileSync(runtimeArchivePath(id),stampLine(`[OrbitHost worker] Auto-start failed: ${error.message}`),{mode:0o600})}catch{}
    });
  }
}
const deployImpl=RUNTIME==='docker'?deployDocker:deployProcess;
const actionImpl=RUNTIME==='docker'?dockerContainerActionDocker:containerActionProcess;
const statusImpl=RUNTIME==='docker'?getStatusDocker:getStatusProcess;
const logsImpl=RUNTIME==='docker'?getLogsDocker:getLogsProcess;
const streamRuntimeLogsImpl=RUNTIME==='docker'?streamRuntimeLogsDocker:streamRuntimeLogsProcess;
if(RUNTIME==='process')recoverProcesses();

app.get('/healthz',(req,res)=>res.json({ok:true,service:'orbithost-worker',bootId:BOOT_ID,runtime:RUNTIME}));
app.use('/v1',auth);
app.get('/v1/healthz',(req,res)=>res.json({ok:true,service:'orbithost-worker',authenticated:true,bootId:BOOT_ID,runtime:RUNTIME}));
const deployHandler=async(req,res)=>{
  try{const result=await deployImpl(req.body,req.file);res.json(result)}catch(error){
    const id=String(req.body?.projectId||'');const oldSecrets=getSecrets(id);const incomingEnv=validateSecretsForRedaction(req.body?.envJson);const secrets=allSecretValues(oldSecrets,incomingEnv);
    if(validId(id))appendBuild(id,`\n[deployment error] ${redact(error.message,secrets)}\n`,secrets);
    const msg=/exit|docker|git|pip|build|clone|ZIP|repository|environment|variable|command|Python/i.test(error.message)?redact(error.message,secrets): 'Deployment failed. Check the worker build logs.';
    res.status(400).json({error:msg});
  }};
app.post('/v1/deploy',upload.single('bundle'),(req,res)=>{if(req.body&&!req.body.projectId&&req.params&&req.params.id)req.body.projectId=req.params.id;return deployHandler(req,res)});
app.post('/v1/projects/:id/deploy',upload.single('bundle'),(req,res)=>{req.body=req.body||{};if(!req.body.projectId)req.body.projectId=req.params.id;return deployHandler(req,res)});
app.post('/v1/projects/:id/action',async(req,res)=>{try{res.json(await actionImpl(req.params.id,req.body?.action))}catch(error){res.status(400).json({error:redact(error.message,getSecrets(req.params.id))})}});
app.get('/v1/projects/:id/status',async(req,res)=>{try{res.json(await statusImpl(req.params.id))}catch(error){res.status(400).json({error:redact(error.message,getSecrets(req.params.id))})}});
app.get('/v1/projects/:id/logs',async(req,res)=>{try{const stream=req.query.stream==='build'?'build':'runtime';res.json(await logsImpl(req.params.id,stream))}catch(error){res.status(400).json({error:redact(error.message,getSecrets(req.params.id))})}});
app.get('/v1/projects/:id/logs/stream',(req,res)=>{
  if(!validId(req.params.id))return res.status(400).json({error:'Invalid project ID.'});
  const stream=req.query.stream==='build'?'build':'runtime';
  if(stream==='build')return streamBuildLogs(req,res,req.params.id);
  return streamRuntimeLogsImpl(req,res,req.params.id);
});
app.use((error,req,res,next)=>{if(res.headersSent)return next(error);const status=error instanceof multer.MulterError?(error.code==='LIMIT_FILE_SIZE'?413:400):500;res.status(status).json({error:status===413?`ZIP exceeds the ${MAX_UPLOAD_MB} MB worker upload limit.`:status===400?'Upload request could not be processed.':'Worker request failed.'})});
app.listen(PORT,'0.0.0.0',()=>console.log(`OrbitHost worker listening on port ${PORT}; protect this service as a host-privileged component.`));
