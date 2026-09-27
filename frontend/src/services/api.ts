export const headers = () => ({'X-API-Key':sessionStorage.getItem('rakshak-key')||''});
export async function api(path:string, options:RequestInit={}) {
  const response=await fetch('/api'+path,{...options,headers:{...headers(),...options.headers}});
  if(!response.ok){const error=await response.json().catch(()=>({detail:'Request failed'}));throw new Error(typeof error.detail==='string'?error.detail:'Invalid request');}
  return response.json();
}
export function upload(file:File,onProgress:(n:number)=>void):Promise<any>{
  return new Promise((resolve,reject)=>{const xhr=new XMLHttpRequest();xhr.open('POST','/api/analyze-email');xhr.setRequestHeader('X-API-Key',headers()['X-API-Key']);xhr.timeout=180000;xhr.upload.onprogress=e=>{if(e.lengthComputable)onProgress(Math.round(e.loaded/e.total*100));};xhr.onload=()=>{try{const data=JSON.parse(xhr.responseText);xhr.status>=200&&xhr.status<300?resolve(data):reject(new Error(data.detail||'Upload failed'));}catch{reject(new Error('Invalid server response'));}};xhr.onerror=()=>reject(new Error('Cannot reach the analysis server.'));xhr.ontimeout=()=>reject(new Error('Analysis timed out. Check investigation history before retrying.'));const data=new FormData();data.append('file',file);xhr.send(data);});
}
