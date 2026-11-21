import {join} from "node:path";
import {access,readFile,readdir} from "node:fs/promises";
import {homedir} from "node:os";
import {exec} from "./exec";
export interface DependencyVulnerability {id:string;pkg:string;installed:string;fixed?:string;severity:string;title:string;target:string;source?:"osv"}
export interface DependencyAudit {status:"ok"|"missing"|"failed"|"unsupported";manager?:string;findings:number;note:string;vulnerabilities?:DependencyVulnerability[]}
const SEVERITY_ORDER=["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"];
/** Scanner output is untrusted: keep short printable text only. */
const clean=(value:unknown,max:number):string=>typeof value==="string"?value.replace(/[^\x20-\x7E]/g," ").replace(/\s+/g," ").trim().slice(0,max):"";
/** Extracts CVE rows from Trivy JSON, worst severity first. */
export function parseTrivyVulnerabilities(parsed:unknown):DependencyVulnerability[]{
 const rows=(parsed as {Results?:unknown[]})?.Results;if(!Array.isArray(rows))return [];
 const found:DependencyVulnerability[]=[];
 for(const row of rows){
  const target=clean((row as {Target?:unknown})?.Target,120);
  const vulns=(row as {Vulnerabilities?:unknown[]})?.Vulnerabilities;if(!Array.isArray(vulns))continue;
  for(const v of vulns as Record<string,unknown>[]){
   const id=clean(v?.VulnerabilityID,40);if(!id)continue;
   const severity=clean(v.Severity,10).toUpperCase()||"UNKNOWN";
   found.push({id,pkg:clean(v.PkgName,120),installed:clean(v.InstalledVersion,40),fixed:clean(v.FixedVersion,80)||undefined,severity,title:clean(v.Title,140),target});
  }
 }
 const rank=(s:string)=>{const i=SEVERITY_ORDER.indexOf(s);return i<0?SEVERITY_ORDER.length:i};
 return found.sort((a,b)=>rank(a.severity)-rank(b.severity)||a.id.localeCompare(b.id));
}
async function exists(path:string):Promise<boolean>{try{await access(path);return true}catch{return false}}
/** Offline-only scanner: Trivy must have a locally cached vulnerability database. */
export async function auditDependencies(root:string,signal?:AbortSignal):Promise<DependencyAudit>{
 const supported:[string,string][]=[["pom.xml","maven"],["package-lock.json","npm"],["requirements.txt","pip"],["poetry.lock","poetry"],["Pipfile.lock","pipenv"],["build.gradle","gradle"],["build.gradle.kts","gradle"],["yarn.lock","yarn"],["pnpm-lock.yaml","pnpm"],["go.mod","go"],["Cargo.lock","cargo"],["composer.lock","composer"],["Gemfile.lock","bundler"],["packages.lock.json","nuget"]];
 // Trivy scans recursively, so manifests in direct subfolders (api/, backend/) count too.
 const dirs=[root];
 try{for(const e of await readdir(root,{withFileTypes:true}))if(e.isDirectory()&&!/^\.|^(?:node_modules|vendor|target|build|dist|out)$/.test(e.name))dirs.push(join(root,e.name))}catch{/* unreadable root */}
 const names:string[]=[];
 for(const [file,name] of supported)for(const dir of dirs){if(!names.includes(name)&&await exists(join(dir,file)))names.push(name)}
 let npmWithoutLock=false;
 if(!names.some(n=>["npm","yarn","pnpm"].includes(n)))for(const dir of dirs)if(await exists(join(dir,"package.json"))){npmWithoutLock=true;break}
 const manager=names.join(", ")||undefined;
 const lockHint="package.json has no lockfile; run npm install --package-lock-only so npm packages can be checked";
 if(!manager)return {status:"unsupported",findings:0,note:npmWithoutLock?lockHint:"No supported dependency manifest found"};
 try{
  const {stdout}=await exec("trivy",["fs","--offline-scan","--skip-db-update","--skip-java-db-update","--scanners","vuln","--format","json","--quiet","."],{
   cwd:root,timeout:120000,maxBuffer:8*1024*1024,windowsHide:true,signal,
   env:{...process.env,TRIVY_DISABLE_VEX_NOTICE:"true"}
  });
  let parsed:unknown;try{parsed=JSON.parse(stdout)}catch{return {status:"failed",manager,findings:0,note:"Scanner output invalid or local vulnerability database unavailable"}}
  const rows=(parsed as {Results?:unknown[]})?.Results;
  if(!Array.isArray(rows))return {status:"failed",manager,findings:0,note:"Scanner did not return complete results"};
  let findings=0;
  for(const row of rows){const vulns=(row as {Vulnerabilities?:unknown[]})?.Vulnerabilities;if(Array.isArray(vulns))findings+=vulns.length}
  const vulnerabilities=parseTrivyVulnerabilities(parsed);
  return {status:"ok",manager,findings,vulnerabilities,note:"Local Trivy database used; coverage depends on cached database freshness and supported ecosystems"+(npmWithoutLock?". "+lockHint:"")};
 }catch(e){
  const err=e as NodeJS.ErrnoException;
  return {status:err.code==="ENOENT"?"missing":"failed",manager,findings:0,note:err.code==="ENOENT"?"Install Trivy and provision its vulnerability database locally first":"Offline scan failed; check local database availability and scanner setup"};
 }
}

export interface GroupedVulnerability extends Omit<DependencyVulnerability,"target"> {targets:string[]}
/** One row per CVE and package version; the same vulnerability in parent and module POMs is listed once. */
export function groupVulnerabilities(list:readonly DependencyVulnerability[]):GroupedVulnerability[]{
 const groups=new Map<string,GroupedVulnerability>();
 for(const v of list){
  const key=[v.id,v.pkg,v.installed].join("|");
  const existing=groups.get(key);
  if(!existing){const {target,...rest}=v;groups.set(key,{...rest,targets:target?[target]:[]})}
  else if(v.target&&!existing.targets.includes(v.target))existing.targets.push(v.target);
 }
 return [...groups.values()];
}
/** 1-based line of the dependency declaration in a manifest, or 1 when it is only inherited (BOM, parent). */
export function findDependencyLine(text:string,pkg:string,installed?:string):number{
 const artifact=pkg.includes(":")?pkg.split(":").pop()!:pkg;
 const escaped=artifact.replace(/[.*+?^${}()|[\]]/g,"\\$&");
 const patterns=[new RegExp("<artifactId>\\s*"+escaped+"\\s*</artifactId>"),new RegExp("[\"']"+escaped+"[\"']"),new RegExp("^\\s*"+escaped+"(?:\\s|[=<>~!;]|$)","i")];
 const lines=text.split(/\r?\n/);
 const esc=(v:string)=>v.replace(/[.*+?^${}()|[\]]/g,"\\$&");
 if(installed){const stem=artifact.split(/[-_.]/)[0];if(stem.length>2)patterns.push(new RegExp("<[\\w.-]*"+esc(stem)+"[\\w.-]*>\\s*"+esc(installed)+"\\s*</"))}
 for(const pattern of patterns){const i=lines.findIndex(l=>pattern.test(l));if(i>=0)return i+1}
 return 1;
}

/** Trivy can list several fixed versions; prefer one in the installed major line (smallest upgrade risk). */
export function firstFixedVersion(fixed:string,installed:string):string|undefined{
 const options=fixed.split(/[,\s]+/).filter(v=>/^v?\d[\w.+-]*$/.test(v));
 const major=installed.split(".")[0];
 return options.find(v=>v.replace(/^v/,"").split(".")[0]===major)??options[0];
}
/** Replaces the installed version with the fixed one on a single manifest line; undefined when the version is not on it. */
export function bumpVersion(line:string,installed:string,fixed:string):string|undefined{
 if(!installed||!fixed||installed===fixed)return undefined;
 const pattern=new RegExp("(?<![\\w.])"+installed.replace(/[.*+?^${}()|[\]]/g,"\\$&")+"(?![\\w.])");
 return pattern.test(line)?line.replace(pattern,()=>fixed):undefined;
}
/** Reads back the marker text written by the dependency scan (VS Code recreates Diagnostic objects). */
export function parseMarkerMessage(message:string):{id:string;pkg:string;installed:string;fixed:string}|undefined{
 const m=/^(\S+) in (\S+) (\S+) \(\w+\)\. Fixed in (.+)\.$/.exec(message);
 return m?{id:m[1],pkg:m[2],installed:m[3],fixed:m[4]}:undefined;
}
/** Writes a CycloneDX SBOM locally; no network access. */
export async function exportSbom(root:string,output:string,signal?:AbortSignal):Promise<{ok:boolean;note:string}>{
 try{
  await exec("trivy",["fs","--offline-scan","--skip-db-update","--skip-java-db-update","--format","cyclonedx","--output",output,"--quiet","."],{cwd:root,timeout:120000,windowsHide:true,signal});
  return {ok:true,note:"SBOM written locally"};
 }catch(e){return {ok:false,note:(e as NodeJS.ErrnoException).code==="ENOENT"?"Install Trivy first":"SBOM export failed"}}
}

/** Whole days since the Trivy vulnerability database was last published, from its metadata.json. */
export function dbAgeDays(metadata:string,now=Date.now()):number|undefined{
 try{
  const updated=Date.parse((JSON.parse(metadata) as {UpdatedAt?:string}).UpdatedAt??"");
  return Number.isFinite(updated)?Math.max(0,Math.floor((now-updated)/86_400_000)):undefined;
 }catch{return undefined}
}
/** Age of the locally cached database, or undefined when it cannot be found. */
export async function trivyDbAgeDays():Promise<number|undefined>{
 const dirs=[process.env.TRIVY_CACHE_DIR,join(homedir(),"Library","Caches","trivy"),join(homedir(),".cache","trivy"),process.env.LOCALAPPDATA&&join(process.env.LOCALAPPDATA,"trivy")];
 for(const dir of dirs){
  if(!dir)continue;
  try{return dbAgeDays(await readFile(join(dir,"db","metadata.json"),"utf8"))}catch{/* try next location */}
 }
 return undefined;
}
