"""Robô IBLACK: lê a planilha de faturamento no OneDrive e atualiza vendas.json (criptografado).
Roda no GitHub Actions. Segredos necessários: PLANILHA_URL (link de compartilhamento do Excel)
e USUARIOS_JSON (lista de usuários e senhas). Só grava o arquivo se algo mudou."""
import os,sys,io,json,gzip,base64,hashlib,collections,urllib.request,datetime
import openpyxl
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ARQ='vendas.json'
MESES=['janeiro','fevereiro','março','abril','maio','junho','julho','agosto','setembro','outubro','novembro','dezembro']
FIX={'Thayson lourenço':'Thayson Lourenço'}
TIPO={'Produtos':'P','Celulares':'C','Assistência Técnica':'A'}
b64=lambda x:base64.b64encode(x).decode(); d64=base64.b64decode
def kdf(salt,it,user,senha): return PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=it).derive((user+'\n'+senha).encode())
def fix(s): s=str(s).strip(); return FIX.get(s,s)

def baixar(url):
    if os.path.exists(url): return open(url,'rb').read()          # teste local
    tent=[]
    if 'sharepoint.com' in url: tent.append(url+('&' if '?' in url else '?')+'download=1')
    else:
        tent.append('https://api.onedrive.com/v1.0/shares/u!'+base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')+'/root/content')
        tent.append(url.replace('redir?','download?').replace('/edit','/download') if 'onedrive.live.com' in url else url+('&' if '?' in url else '?')+'download=1')
    for u in tent:
        try:
            r=urllib.request.urlopen(urllib.request.Request(u,headers={'User-Agent':'Mozilla/5.0'}),timeout=60).read()
            if r[:2]==b'PK': return r
            print('link não devolveu Excel:',u[:80])
        except Exception as e: print('falhou',u[:80],e)
    sys.exit('ERRO: não consegui baixar a planilha. Confira o link de compartilhamento (qualquer pessoa com o link pode ver).')

def ler_planilha(raw):
    wb=openpyxl.load_workbook(io.BytesIO(raw),data_only=True)
    rows=[r for r in list(wb['Alimentação Receitas'].iter_rows(values_only=True))[1:] if r and any(r)]
    mm=collections.Counter((str(r[1]).strip().lower(),int(r[2])) for r in rows if r[0] and r[1] and r[2] and r[7]).most_common(1)
    if not mm: sys.exit('ERRO: planilha sem vendas com mês/ano.')
    (mes,ano),_=mm[0]; ym=f'{ano}-{MESES.index(mes)+1:02d}'
    ws=wb['Base']; metas=[]
    for loja,hr in [('Matriz',17),('Akash',27),('Catuaí',37)]:
        for col in range(12,35,3):
            nome=ws.cell(hr,col).value
            if not nome: continue
            for i,t in enumerate(['Produtos','Celulares','Assistência Técnica']):
                v=ws.cell(hr+2+i,col+2).value
                if isinstance(v,(int,float)) and v: metas.append([fix(nome),loja,t,round(float(v),2)])
    if not metas: sys.exit('ERRO: não achei as metas na aba Base — formato mudou? Nada foi alterado.')
    vendas=[]
    for r in rows:
        if not(r[0] and r[7]) or str(r[1]).strip().lower()!=mes: continue
        if r[4] not in TIPO: print('AVISO tipo desconhecido, ignorado:',r); continue
        vendas.append([f"{int(r[0]):02d}",str(r[3]).strip(),TIPO[r[4]],fix(r[5]),round(float(r[7]),2),str(r[6])])
    desc={v[3] for v in vendas}-{m[0] for m in metas}
    if desc: print('AVISO vendedores sem meta:',desc)
    return ym,{'metas':metas,'vendas':vendas}

def abrir_atual(usuarios):
    E=json.load(open(ARQ))
    for u in usuarios:
        if u['perfil']!='diretoria': continue
        n=u['usuario'].strip().lower(); e=E['usuarios'].get(hashlib.sha256(('iblack:'+n).encode()).hexdigest())
        if not e: continue
        k=json.loads(AESGCM(kdf(d64(e['salt']),E['iter'],n,u['senha'])).decrypt(d64(e['iv']),d64(e['ct']),None))['k']
        p=AESGCM(d64(k)).decrypt(d64(E['iv']),d64(E['ct']),None)
        return json.loads(gzip.decompress(p) if E.get('z') else p)
    sys.exit('ERRO: nenhum usuário da diretoria consegue abrir o vendas.json atual.')

def gravar(D,usuarios,it=250000):
    K=os.urandom(32); iv=os.urandom(12)
    out={"v":2,"z":1,"iter":it,"iv":b64(iv),"ct":b64(AESGCM(K).encrypt(iv,gzip.compress(json.dumps(D,ensure_ascii=False).encode(),9,mtime=0),None)),"usuarios":{}}
    for u in usuarios:
        if u['perfil'] not in ('diretoria','gerente','supervisor','vendedor'): continue
        n=u['usuario'].strip().lower(); salt=os.urandom(16); iu=os.urandom(12)
        pl=json.dumps({"k":b64(K),"nome":u['nome'],"perfil":u['perfil'],"vend":u.get("vend"),"bonus":u.get("bonus")}).encode()
        out["usuarios"][hashlib.sha256(('iblack:'+n).encode()).hexdigest()]={"salt":b64(salt),"iv":b64(iu),"ct":b64(AESGCM(kdf(salt,it,n,u['senha'])).encrypt(iu,pl,None))}
    json.dump(out,open(ARQ,'w'),separators=(',',':'))

def main():
    usuarios=json.loads(os.environ['USUARIOS_JSON']); url=os.environ['PLANILHA_URL'].strip()
    D=abrir_atual(usuarios); ym,novo=ler_planilha(baixar(url))
    antigo=D['meses'].get(ym)
    if antigo==novo: print(f'{ym}: sem mudanças.'); return
    A=collections.Counter(map(tuple,antigo['vendas'])) if antigo else collections.Counter()
    N=collections.Counter(map(tuple,novo['vendas']))
    print(f'{ym}: +{sum((N-A).values())} vendas novas/alteradas, -{sum((A-N).values())} removidas/alteradas, metas {"iguais" if antigo and antigo["metas"]==novo["metas"] else "atualizadas"}')
    D['meses'][ym]=novo; D['atualizado']=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=-3))).strftime('%Y-%m-%d')
    gravar(D,usuarios)
    with open(os.environ.get('GITHUB_OUTPUT','/dev/null'),'a') as f: f.write(f'mudou=1\nmes={ym}\n')

main()
