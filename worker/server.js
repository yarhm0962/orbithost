import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import { spawn } from 'node:child_process';
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
const MAX_UPLOAD_MB = Math.min(100,Math.max(1,Number(process.env.WORKER_MAX_UPLOAD_MB||25)));
const VERSIONS = new Set(['3.10','3.11','3.12','3.13']);
fs.mkdirSync(PROJECTS,{recursive:true,mode:0o700}); fs.mkdirSync(LOGS,{recursive:true,mode:0o700}); fs.mkdirSync(SECRETS,{recursive:true,mode:0o700}); fs.mkdirSync(INCOMING,{recursive:true,mode:0o700});
if (!TOKEN || TOKEN.length < 32 || /replace-with/i.test(TOKEN)) throw new Error('WORKER_TOKEN must be a unique random value of at least 32 characters.');
if (!/^[a-f0-9]{64}$/i.test(process.env.WORKER_ENCRYPTION_KEY||'')) throw new Error('WORKER_ENCRYPTION_KEY must be 64 hex characters.');

app.disable('x-powered-by');
app.use(express.json({limit:'256kb'}));
const upload=multer({storage:multer.diskStorage({destination:(_req,_file,cb)=>cb(null,INCOMING),filename:(_req,_file,cb)=>cb(null,`${crypto.randomUUID()}.zip`)}),limits:{fileSize:MAX_UPLOAD_MB*1024*1024,files:1,fields:10,fieldSize:160000}});
const validId=(id)=>/^[a-f0-9-]{36}$/i.test(String(id||''));
const projectPath=(id)=>path.join(PROJECTS,id);
const buildLogPath=(id)=>path.join(LOGS,`${id}.build.log`);
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
    .replace(/(Bot\s+)[A-Za-z0-9._-]{20,}/g,'$1[REDACTED]').replace(/\x1b\[[0-9;]*m/g,'').slice(-2_000_000);
}
function appendBuild(id,chunk,secrets={}){
  const target=buildLogPath(id); const existing=fs.existsSync(target)?fs.statSync(target).size:0;
  const safe=redact(chunk.toString(),secrets);
  if(existing<2_000_000) fs.appendFileSync(target,safe.slice(0,Math.max(0,2_000_000-existing)),{mode:0o600});
}
function createBuildLogWriter(id,secrets={}){
  const longest=Math.max(0,...Object.values(secrets).filter(v=>typeof v==='string').map(v=>v.length));
  const hold=Math.min(8300,Math.max(256,longest+16));let pending='';
  const write=(value)=>{if(value)appendBuild(id,value,secrets)};
  return {
    push(chunk){const combined=pending+chunk.toString();const count=Math.min(hold,combined.length);const cut=combined.length-count;write(combined.slice(0,cut));pending=combined.slice(cut)},
    flush(){write(pending);pending=''}
  };
}
async function loggedRun(id,command,args,secrets,options={}){
  const writer=createBuildLogWriter(id,secrets);
  try{return await run(command,args,{...options,onOutput:(chunk)=>writer.push(chunk)})}
  finally{writer.flush()}
}
function run(command,args,{cwd,env,timeout=180000,onOutput,cleanEnv=false}={}){
  return new Promise((resolve,reject)=>{
    const inherited=cleanEnv?{PATH:process.env.PATH||'/usr/local/bin:/usr/bin:/bin',HOME:'/tmp',LANG:'C',LC_ALL:'C'}:process.env;
    const child=spawn(command,args,{cwd,env:{...inherited,...env},stdio:['ignore','pipe','pipe'],shell:false});
    let stdout='',stderr='',settled=false;
    const timer=setTimeout(()=>{child.kill('SIGTERM');setTimeout(()=>child.kill('SIGKILL'),3000).unref();},timeout);
    const collect=(dest,chunk)=>{if(onOutput)onOutput(chunk);if(dest==='out')stdout=(stdout+chunk.toString()).slice(-200000);else stderr=(stderr+chunk.toString()).slice(-200000)};
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
          if(++count>2000)return fail('ZIP contains too many files.');
          total+=Number(entry.uncompressedSize||0);if(total>200*1024*1024||Number(entry.uncompressedSize||0)>80*1024*1024)return fail('ZIP expands beyond the size limit.');
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
  await fs.promises.rm(buildLogPath(id),{force:true});
  if(file){
    if(!file.originalname.toLowerCase().endsWith('.zip')||file.size<4)throw new Error('Upload a valid ZIP source archive.');
    const handle=await fs.promises.open(file.path,'r');const header=Buffer.alloc(4);
    try{await handle.read(header,0,4,0)}finally{await handle.close()}
    if(header[0]!==0x50||header[1]!==0x4b)throw new Error('Upload a valid ZIP source archive.');
    await fs.promises.chmod(file.path,0o600);await extractZip(file.path,dir);
  }else{
    const repo=String(body.repositoryUrl||'');if(!safeRepository(repo))throw new Error('Use a public HTTPS Git URL without credentials or query parameters.');
    await run('git',['-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never','clone','--depth','1','--no-recurse-submodules','--',repo,dir],{timeout:120000,cleanEnv:true,env:{GIT_TERMINAL_PROMPT:'0',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'},onOutput:(chunk)=>appendBuild(id,chunk)});
    await fs.promises.rm(path.join(dir,'.git'),{recursive:true,force:true});
  }
  // User-supplied Dockerfiles are deliberately ignored; only the generated, least-privilege runtime is built.
  await fs.promises.rm(path.join(dir,'Dockerfile'),{force:true});
  return dir;
}
function validateEnvironment(raw){
  const env=safeJson(raw||'{}');if(!env||Array.isArray(env)||typeof env!=='object')throw new Error('Invalid environment variable payload.');
  const keys=Object.keys(env);if(keys.length>100)throw new Error('A project can have at most 100 environment variables.');
  let size=0;for(const [k,v] of Object.entries(env)){if(!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(k))throw new Error(`Invalid environment variable name: ${k}`);if(typeof v!=='string'||v.includes('\n')||v.includes('\r')||v.includes('\0')||v.length>8192)throw new Error(`Invalid value for environment variable ${k}.`);size+=k.length+v.length}
  if(size>120000)throw new Error('Environment variables exceed the size limit.');return env;
}
async function deploy(body,file){
  const id=String(body.projectId||'');if(!validId(id))throw new Error('Invalid project ID.');
  const version=String(body.pythonVersion||'3.12');if(!VERSIONS.has(version))throw new Error('Unsupported Python version.');
  const buildCommand=String(body.buildCommand||'').slice(0,500);const startCommand=String(body.startCommand||'python main.py').trim().slice(0,500);
  if(!startCommand)throw new Error('Start command is required.');
  const env=validateEnvironment(body.envJson);const envValues=Object.values(env);
  await fs.promises.writeFile(secretPath(id),encrypt(env),{mode:0o600});
  const dir=await ensureSource(body,file,id);
  const dockerfile=[
    `FROM python:${version}-slim`,
    'ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp PATH="/opt/venv/bin:$PATH"',
    'RUN useradd --no-create-home --uid 10001 --shell /usr/sbin/nologin bot && python -m venv /opt/venv && chown -R 10001:10001 /opt/venv',
    'WORKDIR /app',
    'COPY --chown=bot:bot . /app',
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
  await loggedRun(id,'docker',['build','--pull','--tag',image,'--file',path.join(dir,'Dockerfile'),dir],env,{timeout:12*60*1000});
  log('\n[OrbitHost worker] Image built. Starting isolated bot container…\n');
  // Docker env-file avoids putting secret values in command-line arguments and process listings.
  const envFile=path.join(os.tmpdir(),`orbithost-env-${id}-${crypto.randomUUID()}`);
  try{
    const lines=Object.entries(env).map(([k,v])=>`${k}=${v}`).join('\n')+(Object.keys(env).length?'\n':'');
    await fs.promises.writeFile(envFile,lines,{mode:0o600,flag:'wx'});
    await run('docker',['rm','--force',name],{timeout:15000}).catch(()=>{});
    await run('docker',['network','rm',network],{timeout:15000}).catch(()=>{});
    await run('docker',['network','create',network],{timeout:15000});
    await loggedRun(id,'docker',['run','--detach','--init','--name',name,'--label',`com.orbithost.project=${id}`,'--restart','unless-stopped','--memory=256m','--memory-swap=256m','--cpus=0.50','--pids-limit=128','--read-only','--security-opt=no-new-privileges:true','--cap-drop=ALL','--user=10001:10001','--network',network,'--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777','--env-file',envFile,'--env','PYTHONUNBUFFERED=1','--env','HOME=/tmp',image],env,{timeout:60000});
  }finally{await fs.promises.rm(envFile,{force:true})}
  log('\n[OrbitHost worker] Container started. No host ports are published.\n');
  return {status:'online',containerId:name,pythonVersion:version};
}
async function dockerContainerAction(id,action){
  if(!validId(id))throw new Error('Invalid project ID.');const name=`orbithost-${id}`;
  if(action==='delete'){
    await run('docker',['rm','--force',name],{timeout:30000}).catch(()=>{});
    await run('docker',['image','rm',`orbithost:${id}`],{timeout:30000}).catch(()=>{});
    await run('docker',['network','rm',`orbithost-net-${id}`],{timeout:15000}).catch(()=>{});
    await fs.promises.rm(projectPath(id),{recursive:true,force:true});await fs.promises.rm(buildLogPath(id),{force:true});await fs.promises.rm(secretPath(id),{force:true});return {status:'deleted'};
  }
  if(!['start','stop','restart'].includes(action))throw new Error('Unsupported action.');
  await run('docker',[action,name],{timeout:30000});return {status:action==='stop'?'stopped':'online'};
}
async function getStatus(id){
  if(!validId(id))throw new Error('Invalid project ID.');const name=`orbithost-${id}`;
  let inspect;
  try{const {stdout}=await run('docker',['inspect','--format','{{json .State}}|{{.HostConfig.Memory}}|{{.Name}}',name],{timeout:12000});inspect=stdout.trim()}catch{return {status:'stopped',cpuPercent:0,memoryMb:0,memoryLimitMb:256,uptime:0,mode:'container'}}
  const [statePart,memLimit]=inspect.split('|');const state=safeJson(statePart)||{};let stats='';
  if(state.Running)try{stats=(await run('docker',['stats','--no-stream','--format','{{.CPUPerc}}|{{.MemUsage}}',name],{timeout:12000})).stdout.trim()}catch{}
  let cpu=0,memory=0;const [cpuText,memText]=stats.split('|');if(cpuText)cpu=Number.parseFloat(cpuText)||0;if(memText){const m=memText.match(/([\d.]+)\s*(MiB|GiB|MB|GB|KiB|KB)/i);if(m){memory=Number(m[1]);if(/^g/i.test(m[2]))memory*=1024;else if(/^k/i.test(m[2]))memory/=1024}}
  const started=state.StartedAt&&state.StartedAt.startsWith('0001-')?null:Date.parse(state.StartedAt||'');
  return {status:state.Running?'online':(state.Status==='exited'?'stopped':state.Status||'stopped'),cpuPercent:Number(cpu.toFixed(1)),memoryMb:Math.round(memory),memoryLimitMb:Math.round((Number(memLimit)||268435456)/1048576),uptime:state.Running&&started?Math.max(0,Math.floor((Date.now()-started)/1000)):0,mode:'container'};
}
async function getLogs(id,stream){
  if(!validId(id))throw new Error('Invalid project ID.');let text='';
  if(stream==='build')text=await fs.promises.readFile(buildLogPath(id),'utf8').catch(()=> '');
  else text=await run('docker',['logs','--timestamps','--tail','500',`orbithost-${id}`],{timeout:15000}).then(x=>x.stdout+'\n'+x.stderr).catch(e=>String(e.message).includes('No such container')?'':Promise.reject(e));
  const safe=redact(text,getSecrets(id));const entries=safe.split(/\r?\n/).filter(Boolean).slice(-500).map((message,i)=>({id:`${stream}-${i}`,stream,level:/error|exception|traceback|failed/i.test(message)?'error':/warn/i.test(message)?'warn':'info',message,createdAt:new Date().toISOString()}));
  return entries;
}
app.get('/healthz',(req,res)=>res.json({ok:true,service:'orbithost-worker'}));
app.use('/v1',auth);
app.post('/v1/deploy',upload.single('bundle'),async(req,res)=>{
  try{const result=await deploy(req.body,req.file);res.json(result)}catch(error){
    const id=String(req.body?.projectId||'');if(validId(id))appendBuild(id,`\n[deployment error] ${redact(error.message,getSecrets(id))}\n`,getSecrets(id));
    const msg=/exit|docker|git|pip|build|clone|ZIP|repository|environment|variable|command|Python/i.test(error.message)?redact(error.message,getSecrets(id)): 'Deployment failed. Check the worker build logs.';
    res.status(400).json({error:msg});
  }finally{if(req.file?.path)await fs.promises.rm(req.file.path,{force:true}).catch(()=>{})}
});
app.post('/v1/projects/:id/action',async(req,res)=>{try{res.json(await dockerContainerAction(req.params.id,req.body?.action))}catch(error){res.status(400).json({error:redact(error.message,getSecrets(req.params.id))})}});
app.get('/v1/projects/:id/status',async(req,res)=>{try{res.json(await getStatus(req.params.id))}catch(error){res.status(400).json({error:redact(error.message,getSecrets(req.params.id))})}});
app.get('/v1/projects/:id/logs',async(req,res)=>{try{const stream=req.query.stream==='build'?'build':'runtime';res.json({entries:await getLogs(req.params.id,stream)})}catch(error){res.status(400).json({error:redact(error.message,getSecrets(req.params.id))})}});
app.use((error,req,res,next)=>{if(res.headersSent)return next(error);const status=error instanceof multer.MulterError?(error.code==='LIMIT_FILE_SIZE'?413:400):500;res.status(status).json({error:status===413?`ZIP exceeds the ${MAX_UPLOAD_MB} MB worker upload limit.`:status===400?'Upload request could not be processed.':'Worker request failed.'})});
app.listen(PORT,'0.0.0.0',()=>console.log(`OrbitHost worker listening on port ${PORT}; protect this service as a host-privileged component.`));
