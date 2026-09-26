'use strict';

/* =========================================================
   1. CONFIGURAÇÃO DE SEGURANÇA
   ========================================================= */
const CONFIG = {
  MAX_TENTATIVAS: 5,          // falhas seguidas antes do bloqueio
  BLOQUEIO_MS: 60 * 1000,     // tempo de bloqueio da conta (rate limit)
  TOKEN_TTL_S: 15 * 60,       // validade do JWT: 15 minutos
  PBKDF2_ITER: 600000,        // custo do hash de senha (recomendação OWASP para PBKDF2-HMAC-SHA256)
  EMAIL_MAX: 254,
  SENHA_MIN: 8,
  SENHA_MAX: 64
};

/* =========================================================
   2. BASE DE USUÁRIOS (simula o banco da API)
   Senhas guardadas só como hash PBKDF2-SHA256 com salt único.
   ========================================================= */
const USUARIOS = [
  { id:'u-1001', email:'cliente@demo.com',  nome:'Mariana Souza', perfil:'cliente',
    salt:'b25b2c7177d166d1a8130495a6c0d8f0', hash:'519dca67efe6904af3298d137ad781300f84a17abddddc620b421f35ba6bdfb7' },
  { id:'u-2001', email:'analista@ford.com', nome:'Rafael Lima',   perfil:'analista',
    salt:'6f12f5b03e03ee29ca857ed35e0943fc', hash:'e788b6aaa63b2ff731ca51cd3084025f3ceb9fcef79462eb69fc359e9aacab08' },
  { id:'u-9001', email:'admin@ford.com',    nome:'Carla Mendes',  perfil:'admin',
    salt:'0895e1de52b5c81d589524bba5871119', hash:'938c647da6230e6a633d080f9c964ca099796b61e71c0e9daa85977661736b32' },
  // Contas sem senha de demonstração: aparecem na gestão do Administrador
  { id:'u-1002', email:'pedro.alves@email.com',  nome:'Pedro Alves',    perfil:'cliente' },
  { id:'u-2002', email:'juliana.castro@ford.com', nome:'Juliana Castro', perfil:'analista' }
];
// Campos mutáveis de cada conta: versaoToken (revogação de sessões) e ultimoLogin
USUARIOS.forEach(u => { u.versaoToken = 0; u.ultimoLogin = null; });
// Salt usado quando o e-mail não existe: o tempo de resposta fica igual (evita enumeração de usuários)
const SALT_FALSO = '0a30c861686b81fc362f1ebd76bc3b1d';

const PERFIS = {
  cliente:  { rotulo:'Cliente',        acesso:'Somente os próprios dados e veículos' },
  analista: { rotulo:'Analista Ford',  acesso:'Leads e dashboards das concessionárias' },
  admin:    { rotulo:'Administrador',  acesso:'Configurações globais e auditoria' }
};

// Contas exibidas na tela de login só para a demonstração.
// Triagem Semgrep: RISCO ACEITO. São senhas públicas de um protótipo, mostradas na própria tela;
// não existem em nenhum ambiente real. Em produção este bloco não existe.
const CONTAS_TESTE = [
  { email:'cliente@demo.com',  senha:'Cliente@2026',  perfil:'cliente' },  // nosemgrep: ford.segredo-fixo-no-codigo
  { email:'analista@ford.com', senha:'Analista@2026', perfil:'analista' }, // nosemgrep: ford.segredo-fixo-no-codigo
  { email:'admin@ford.com',    senha:'Admin@2026',    perfil:'admin' }     // nosemgrep: ford.segredo-fixo-no-codigo
];

/* =========================================================
   3. LOG ESTRUTURADO (JSON)
   ========================================================= */
// IP público simulado do aparelho (em produção vem do gateway da API, não do app)
const IP_ORIGEM = '177.72.14.203';

const Log = {
  itens: [],
  registrar(evento, nivel, dados = {}) {
    const entrada = {
      timestamp: new Date().toISOString(),
      level: nivel,
      event: evento,
      trace_id: crypto.randomUUID(),
      source: 'app-mobile',
      ip: IP_ORIGEM,
      app_version: '0.8.0',
      ...dados
    };
    this.itens.push(entrada);
    desenharLog(entrada);
    Monitor.processar(entrada); // seção 23: regras de alerta avaliadas em tempo real
    return entrada;
  }
};

function mascararEmail(email) {
  const [u, d] = String(email).split('@');
  if (!d) return '***';
  return u.slice(0, 1) + '***@' + d;
}

// Pseudônimo estável da conta para os logs. O e-mail mascarado ("a***@ford.com") colide entre
// contas diferentes; este código não colide e não revela o e-mail.
// Em produção: HMAC-SHA256 com uma chave (pepper) guardada no cofre de segredos.
function refConta(email) {
  return 'acc-' + hashSimples('ford-log-pepper|' + String(email).toLowerCase()).toString(16).padStart(8, '0');
}

function desenharLog(entrada) {
  const lista = document.getElementById('logList');
  const vazio = lista.querySelector('.empty');
  if (vazio) vazio.remove();
  const li = document.createElement('li');
  li.className = entrada.level;
  const pre = document.createElement('pre');
  pre.textContent = JSON.stringify(entrada, null, 2); // textContent: nunca interpreta HTML
  li.appendChild(pre);
  lista.appendChild(li);
}

function logVazio() {
  const lista = document.getElementById('logList');
  lista.innerHTML = '<li class="empty" style="border:0">Nenhum evento ainda. Faça um login para gerar registros.</li>';
}

/* =========================================================
   4. VALIDAÇÃO E SANITIZAÇÃO DE ENTRADA
   ========================================================= */
const REGEX_EMAIL = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;

function normalizarEmail(v) {
  return String(v || '').trim().toLowerCase();
}

function validarLogin(email, senha) {
  const erros = {};
  if (!email) erros.email = 'Informe seu e-mail.';
  else if (email.length > CONFIG.EMAIL_MAX || !REGEX_EMAIL.test(email))
    erros.email = 'Digite um e-mail válido, como nome@dominio.com.';
  if (!senha) erros.senha = 'Informe sua senha.';
  else if (senha.length < CONFIG.SENHA_MIN || senha.length > CONFIG.SENHA_MAX)
    erros.senha = `A senha tem entre ${CONFIG.SENHA_MIN} e ${CONFIG.SENHA_MAX} caracteres.`;
  return erros;
}

/* =========================================================
   5. RATE LIMIT / BLOQUEIO POR TENTATIVAS
   ========================================================= */
const tentativas = new Map(); // email -> { falhas, bloqueadoAte }

function estadoBloqueio(email) {
  const t = tentativas.get(email);
  if (t && t.bloqueadoAte > Date.now()) return t.bloqueadoAte - Date.now();
  return 0;
}

function registrarFalha(email) {
  const t = tentativas.get(email) || { falhas: 0, bloqueadoAte: 0 };
  t.falhas += 1;
  if (t.falhas >= CONFIG.MAX_TENTATIVAS) {
    t.bloqueadoAte = Date.now() + CONFIG.BLOQUEIO_MS;
    t.falhas = 0;
    tentativas.set(email, t);
    return { bloqueou: true, restantes: 0 };
  }
  tentativas.set(email, t);
  return { bloqueou: false, restantes: CONFIG.MAX_TENTATIVAS - t.falhas };
}

/* =========================================================
   6. HASH DE SENHA (PBKDF2) E COMPARAÇÃO EM TEMPO CONSTANTE
   ========================================================= */
const enc = new TextEncoder();
const hexParaBytes = h => new Uint8Array(h.match(/../g).map(b => parseInt(b, 16)));
const bytesParaHex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');

async function derivarHash(senha, saltHex) {
  const chave = await crypto.subtle.importKey('raw', enc.encode(senha), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexParaBytes(saltHex), iterations: CONFIG.PBKDF2_ITER, hash: 'SHA-256' },
    chave, 256);
  return bytesParaHex(bits);
}

function iguaisTempoConstante(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function autenticar(email, senha) {
  const u = USUARIOS.find(x => x.email === email);
  const hash = await derivarHash(senha, u && u.salt ? u.salt : SALT_FALSO);
  return u && u.hash && iguaisTempoConstante(hash, u.hash) ? u : null;
}

/* =========================================================
   7. JWT (HS256) COM CHAVE NÃO EXPORTÁVEL
   Payload sem dados pessoais: só id, perfil, emissão, validade e jti.
   ========================================================= */
let chaveJWT = null;
let chaveJWTAnterior = null; // após rotação: distingue token antigo (esperado) de token forjado (ataque)

async function iniciarChaveJWT() {
  chaveJWT = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

// Quem emite o token e para quem ele serve (ASVS 5.0, V9.2: aceitar só tokens destinados a este serviço)
const JWT_ISS = 'ford-posvenda-api';
const JWT_AUD = 'ford-posvenda-app';

const b64url = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlJson = obj => b64url(enc.encode(JSON.stringify(obj)));
const b64urlParaBytes = s => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
};

async function emitirToken(usuario) {
  const agora = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  // ver = versão do token da conta. Quando o admin muda o perfil ou encerra as sessões, a versão sobe e tokens antigos morrem.
  const payload = { iss: JWT_ISS, aud: JWT_AUD, sub: usuario.id, role: usuario.perfil, ver: usuario.versaoToken, iat: agora, exp: agora + CONFIG.TOKEN_TTL_S, jti: crypto.randomUUID() };
  const base = b64urlJson(header) + '.' + b64urlJson(payload);
  const assinatura = await crypto.subtle.sign('HMAC', chaveJWT, enc.encode(base));
  return base + '.' + b64url(assinatura);
}

// Retorna { payload, motivo }. motivo explica a recusa para o log (nunca para o usuário).
async function analisarToken(token) {
  try {
    const [h, p, s] = String(token || '').split('.');
    if (!h || !p || !s) return { payload: null, motivo: 'malformed' };
    const header = JSON.parse(new TextDecoder().decode(b64urlParaBytes(h)));
    if (header.alg !== 'HS256') return { payload: null, motivo: 'alg_not_allowed' }; // recusa "alg: none"
    if (header.typ !== 'JWT') return { payload: null, motivo: 'malformed' };
    const ok = await crypto.subtle.verify('HMAC', chaveJWT, b64urlParaBytes(s), enc.encode(h + '.' + p));
    if (!ok) {
      const antiga = chaveJWTAnterior && await crypto.subtle.verify('HMAC', chaveJWTAnterior, b64urlParaBytes(s), enc.encode(h + '.' + p));
      return { payload: null, motivo: antiga ? 'key_rotated' : 'signature_mismatch' };
    }
    const payload = JSON.parse(new TextDecoder().decode(b64urlParaBytes(p)));
    if (payload.iss !== JWT_ISS || payload.aud !== JWT_AUD) return { payload: null, motivo: 'invalid_claims' };
    if (typeof payload.exp !== 'number' || payload.exp <= Math.floor(Date.now() / 1000)) return { payload: null, motivo: 'expired' };
    const dono = USUARIOS.find(u => u.id === payload.sub);
    if (!dono || dono.versaoToken !== payload.ver || dono.perfil !== payload.role) return { payload: null, motivo: 'revoked' };
    return { payload, motivo: null };
  } catch { return { payload: null, motivo: 'malformed' }; }
}

async function verificarToken(token) {
  return (await analisarToken(token)).payload;
}

/* =========================================================
   8. SESSÃO (somente em memória, nunca em localStorage)
   ========================================================= */
let sessao = null;       // { token }
let timerSessao = null;

async function exigirSessao(perfisPermitidos) {
  const payload = sessao ? await verificarToken(sessao.token) : null;
  if (!payload) return null;
  if (perfisPermitidos && !perfisPermitidos.includes(payload.role)) {
    Log.registrar('access.denied', 'WARN', { user_id: payload.sub, role: payload.role, reason: 'perfil_sem_permissao' });
    return null;
  }
  return payload;
}

function encerrarSessao(motivo) {
  if (!sessao) return;
  if (motivo !== 'excluida') verificarToken(sessao.token).then(p => {
    Log.registrar(motivo === 'expirou' ? 'auth.token.expired' : 'auth.logout', 'INFO',
      { user_id: p ? p.sub : 'desconhecido', outcome: 'session_closed' });
  });
  sessao = null;
  clearInterval(timerSessao);
  CacheSeguro.limpar();          // apaga dados cifrados e descarta a chave AES
  ativarSimulacoes(false);
  const avisos = {
    expirou: 'Sua sessão expirou. Entre novamente para continuar.',
    seguranca: 'Sua sessão foi encerrada pela equipe de segurança. Entre novamente.',
    excluida: 'Conta excluída. Seus dados pessoais foram removidos. No protótipo, recarregue a página para restaurar a conta de teste.'
  };
  telaLogin(avisos[motivo] || null);
}

/* =========================================================
   9. TELAS
   ========================================================= */
const tela = document.getElementById('screen');
// Toda tela nova começa do topo (observa só a troca de tela, não as atualizações internas)
new MutationObserver(() => { tela.scrollTop = 0; }).observe(tela, { childList: true });

function telaLogin(aviso) {
  tela.innerHTML = `
    <div class="hero">
      <p class="brand">Ford Pós-Venda</p>
      <h1>Entre na sua conta</h1>
      <p>Acompanhe revisões, garantia e agendamentos do seu Ford.</p>
    </div>
    <form class="form" id="formLogin" novalidate autocomplete="on">
      <div id="msg" role="alert"></div>
      <div class="field">
        <label for="email">E-mail</label>
        <input id="email" name="email" type="email" inputmode="email" autocomplete="username" aria-describedby="erroEmail">
        <div class="hint" id="erroEmail"></div>
      </div>
      <div class="field">
        <label for="senha">Senha</label>
        <div class="input-wrap">
          <input id="senha" name="senha" type="password" autocomplete="current-password" aria-describedby="erroSenha" style="padding-right:84px">
          <button type="button" class="toggle-pass" id="toggleSenha" aria-pressed="false">Mostrar</button>
        </div>
        <div class="hint" id="erroSenha"></div>
      </div>
      <button class="btn btn-primary" id="btnEntrar" type="submit">Entrar</button>
    </form>
    <section class="demo" aria-labelledby="tituloDemo">
      <h2 id="tituloDemo">Contas de teste</h2>
      <div class="demo-list" id="demoList"></div>
    </section>
    <p class="foot">
      <svg width="14" height="16" viewBox="0 0 14 16" aria-hidden="true" style="flex:none;margin-top:1px"><rect x="1" y="7" width="12" height="8.5" rx="2" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M4 7V4.8a3 3 0 0 1 6 0V7" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>
      <span>Conexão protegida com TLS 1.2 ou superior. Seus dados são tratados conforme a LGPD.</span>
    </p>`;

  // Limites aplicados pelo DOM: o innerHTML acima fica só com HTML fixo (regra ford.xss-innerhtml-dinamico)
  document.getElementById('email').maxLength = CONFIG.EMAIL_MAX;
  document.getElementById('senha').maxLength = CONFIG.SENHA_MAX;

  const lista = document.getElementById('demoList');
  CONTAS_TESTE.forEach(c => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'demo-btn';
    const txt = document.createElement('span');
    const forte = document.createElement('strong');
    forte.textContent = PERFIS[c.perfil].rotulo;
    const det = document.createElement('span');
    det.textContent = `${c.email} / ${c.senha}`;
    txt.append(forte, det);
    const acao = document.createElement('em');
    acao.textContent = 'Preencher';
    b.append(txt, acao);
    b.addEventListener('click', () => {
      document.getElementById('email').value = c.email;
      document.getElementById('senha').value = c.senha;
      document.getElementById('senha').focus();
      sincronizarBloqueio();
    });
    lista.appendChild(b);
  });

  if (aviso) mostrarMsg('warn', aviso);

  document.getElementById('toggleSenha').addEventListener('click', e => {
    const campo = document.getElementById('senha');
    const mostrar = campo.type === 'password';
    campo.type = mostrar ? 'text' : 'password';
    e.currentTarget.textContent = mostrar ? 'Ocultar' : 'Mostrar';
    e.currentTarget.setAttribute('aria-pressed', String(mostrar));
  });

  document.getElementById('email').addEventListener('input', sincronizarBloqueio);
  document.getElementById('formLogin').addEventListener('submit', aoEnviarLogin);
}

// O bloqueio é por conta: ao trocar o e-mail, o botão reflete o estado da conta digitada
function sincronizarBloqueio() {
  const email = normalizarEmail(document.getElementById('email').value);
  if (estadoBloqueio(email)) return exibirBloqueio(email);
  clearInterval(contadorBloqueio);
  const btn = document.getElementById('btnEntrar');
  if (btn.disabled && btn.textContent.startsWith('Tente')) {
    btn.disabled = false;
    btn.textContent = 'Entrar';
    mostrarMsg(null, null);
  }
}

function mostrarMsg(tipo, texto) {
  const box = document.getElementById('msg');
  if (!box) return;
  box.innerHTML = '';
  if (!texto) return;
  const d = document.createElement('div');
  d.className = 'alert ' + (tipo === 'erro' ? 'alert-error' : 'alert-warn');
  d.textContent = texto;
  box.appendChild(d);
}

function marcarErros(erros) {
  // Triagem Semgrep: FALSO POSITIVO. 'erroSenha' é o id de um elemento da tela, não um segredo.
  const campos = { email: 'erroEmail', senha: 'erroSenha' }; // nosemgrep: ford.segredo-fixo-no-codigo
  Object.entries(campos).forEach(([campo, idErro]) => {
    const input = document.getElementById(campo);
    input.setAttribute('aria-invalid', erros[campo] ? 'true' : 'false');
    document.getElementById(idErro).textContent = erros[campo] || '';
  });
}

let contadorBloqueio = null;
function exibirBloqueio(email) {
  const btn = document.getElementById('btnEntrar');
  clearInterval(contadorBloqueio);
  const tick = () => {
    const ms = estadoBloqueio(email);
    if (!ms) {
      clearInterval(contadorBloqueio);
      btn.disabled = false;
      btn.textContent = 'Entrar';
      mostrarMsg(null, null);
      return;
    }
    btn.disabled = true;
    btn.textContent = `Tente de novo em ${Math.ceil(ms / 1000)}s`;
  };
  tick();
  contadorBloqueio = setInterval(tick, 1000);
}

async function aoEnviarLogin(ev) {
  ev.preventDefault();
  const email = normalizarEmail(document.getElementById('email').value);
  const senha = document.getElementById('senha').value;
  const btn = document.getElementById('btnEntrar');

  // 1) Validação de entrada
  const erros = validarLogin(email, senha);
  marcarErros(erros);
  if (Object.keys(erros).length) {
    Log.registrar('auth.login.invalid_input', 'WARN', { user: mascararEmail(email), account_ref: refConta(email), fields: Object.keys(erros) });
    return;
  }

  // 2) Origem bloqueada pela resposta a incidentes?
  if (ipBloqueado()) {
    Log.registrar('waf.blocked', 'WARN', { route: 'login', status: 403, reason: 'ip_blocked_by_incident_response' });
    mostrarMsg('erro', 'Acesso temporariamente bloqueado pela equipe de segurança.');
    return;
  }

  // 3) Conta bloqueada?
  if (estadoBloqueio(email)) {
    Log.registrar('auth.login.blocked_attempt', 'WARN', { user: mascararEmail(email), account_ref: refConta(email), outcome: 'rejected_locked' });
    mostrarMsg('erro', 'Muitas tentativas. Aguarde para tentar novamente.');
    exibirBloqueio(email);
    return;
  }

  // 3) Autenticação
  btn.disabled = true;
  btn.textContent = 'Verificando...';
  const usuario = await autenticar(email, senha);

  if (!usuario) {
    const r = registrarFalha(email);
    Log.registrar('auth.login.failure', 'WARN', { user: mascararEmail(email), account_ref: refConta(email), outcome: 'invalid_credentials', attempts_left: r.restantes });
    if (r.bloqueou) {
      Log.registrar('auth.account.lockout', 'CRITICAL', {
        user: mascararEmail(email), account_ref: refConta(email), reason: 'brute_force_suspected',
        threshold: CONFIG.MAX_TENTATIVAS, lock_seconds: CONFIG.BLOQUEIO_MS / 1000
      });
      mostrarMsg('erro', `Conta bloqueada por ${CONFIG.BLOQUEIO_MS / 1000} segundos após ${CONFIG.MAX_TENTATIVAS} tentativas sem sucesso.`);
      exibirBloqueio(email);
      return;
    }
    // Mensagem genérica: não revela se o e-mail existe
    mostrarMsg('erro', `E-mail ou senha incorretos. Restam ${r.restantes} tentativas.`);
    btn.disabled = false;
    btn.textContent = 'Entrar';
    return;
  }

  // 4) Sucesso: zera tentativas, emite token e guarda só em memória
  tentativas.delete(email);
  usuario.ultimoLogin = new Date().toISOString();
  sessao = { token: await emitirToken(usuario), perfil: usuario.perfil };
  Log.registrar('auth.login.success', 'INFO', { user_id: usuario.id, role: usuario.perfil, outcome: 'token_issued', token_ttl_s: CONFIG.TOKEN_TTL_S });
  rotearInicio();
}

// Cada perfil tem sua tela inicial
async function rotearInicio() {
  const payload = await exigirSessao(['cliente', 'analista', 'admin']);
  if (!payload) return encerrarSessao('expirou');
  ativarSimulacoes(payload.role);
  if (payload.role === 'cliente') {
    await CacheSeguro.iniciar();
    return telaCliente();
  }
  if (payload.role === 'analista') return telaAnalista();
  return telaAdmin();
}

/* =========================================================
   10. BASE DE VEÍCULOS (simula o banco da API)
   ========================================================= */
const minutosAtras = m => new Date(Date.now() - m * 60000).toISOString();

const VEICULOS_DB = [
  { id:'v-5001', ownerId:'u-1001', modelo:'Ranger', versao:'XLS 2.0 Diesel 4x4 AT', ano:2024,
    placa:'BRA2E19', vin:'9BFBXXLB6RBY20417', km:38420, telemetriaEm:minutosAtras(12),
    entrega:'2024-02-10', garantiaFim:'2027-02-10',
    plano:{ intervaloKm:10000, intervaloMeses:12 },
    ultimaRevisao:{ km:30000, data:'2025-10-20' },
    historico:[
      { data:'2025-10-20', servico:'Revisão dos 30.000 km', local:'Concessionária Via Norte, São Paulo' },
      { data:'2025-03-02', servico:'Revisão dos 20.000 km', local:'Concessionária Via Norte, São Paulo' },
      { data:'2024-09-15', servico:'Revisão dos 10.000 km', local:'Concessionária Paulista Motors, São Paulo' }
    ] },
  { id:'v-5002', ownerId:'u-1001', modelo:'Territory', versao:'Titanium 1.5 EcoBoost', ano:2025,
    placa:'FRD7C32', vin:'LVSHCFAE1SF508213', km:8940, telemetriaEm:minutosAtras(95),
    entrega:'2025-06-05', garantiaFim:'2028-06-05',
    plano:{ intervaloKm:10000, intervaloMeses:12 },
    ultimaRevisao:null,
    historico:[] },
  // Veículo de OUTRO cliente: usado para testar a proteção contra IDOR/BOLA
  { id:'v-5099', ownerId:'u-1002', modelo:'Maverick', versao:'Lariat Hybrid', ano:2025,
    placa:'XYZ9A99', vin:'3FTTW8E3XSRA12345', km:15200, telemetriaEm:minutosAtras(40),
    entrega:'2025-01-20', garantiaFim:'2028-01-20',
    plano:{ intervaloKm:10000, intervaloMeses:12 },
    ultimaRevisao:{ km:10000, data:'2025-11-02' }, historico:[] }
];

function mascararVin(vin) {
  return vin.slice(0, 3) + '•'.repeat(8) + vin.slice(-6);
}

// DTO: só o que o app precisa. Sem ownerId, e o VIN sai mascarado (minimização, LGPD)
function veiculoDTO(v) {
  return {
    id: v.id, modelo: v.modelo, versao: v.versao, ano: v.ano, placa: v.placa,
    vin_mascarado: mascararVin(v.vin), km: v.km,
    telemetria_em: consentimentosDe(v.ownerId).telemetria ? v.telemetriaEm : null, // sem consentimento, sem telemetria
    entrega: v.entrega, garantia_fim: v.garantiaFim, plano: v.plano,
    ultima_revisao: v.ultimaRevisao, historico: v.historico,
    agendamento_ativo: (a => (a ? agendamentoDTO(a) : null))(agendamentoAtivo(v.id))
  };
}

/* =========================================================
   11. API SIMULADA (autenticação, rate limit, autorização por objeto)
   ========================================================= */
const LIMITE_API = { max: 30, janelaMs: 60 * 1000 }; // 30 requisições por minuto por usuário
const janelasApi = new Map();                         // user_id -> { inicio, qtd, avisado }

function checarLimite(sub) {
  const agora = Date.now();
  let j = janelasApi.get(sub);
  if (!j || agora - j.inicio > LIMITE_API.janelaMs) {
    j = { inicio: agora, qtd: 0, avisado: false };
    janelasApi.set(sub, j);
  }
  j.qtd += 1;
  if (j.qtd <= LIMITE_API.max) return null;
  const retry = Math.ceil((j.inicio + LIMITE_API.janelaMs - agora) / 1000);
  if (!j.avisado) { // registra uma vez por janela para não inundar o log
    j.avisado = true;
    Log.registrar('api.rate_limited', 'WARN', { user_id: sub, limit_per_min: LIMITE_API.max, status: 429, retry_after_s: retry });
  }
  return { status: 429, erro: 'Muitas requisições. Tente novamente em instantes.', retry_after: retry };
}

function negar(payload, rota, motivo, status, erro) {
  Log.registrar('access.denied', 'WARN', { user_id: payload.sub, role: payload.role, route: rota, reason: motivo, status });
  return { status, erro };
}

// A10:2025 (tratamento de condições excepcionais): se algo inesperado quebrar dentro da API,
// a resposta é um 500 genérico. Nunca devolve dado parcial, stack trace ou mensagem interna.
async function api(metodo, rota, token, opcoes = {}) {
  try {
    return await apiInterna(metodo, rota, token, opcoes);
  } catch (e) {
    Log.registrar('api.internal_error', 'CRITICAL', { method: metodo, route: String(rota).replace(/[a-z]-\d{4}/g, '{id}'), error_type: (e && e.name) || 'Error', status: 500 });
    return { status: 500, erro: 'Não foi possível concluir agora. Tente novamente em instantes.' };
  }
}

async function apiInterna(metodo, rota, token, opcoes = {}) {
  // 0) Origem bloqueada pela equipe de resposta a incidentes (seção 25)
  if (ipBloqueado()) {
    Log.registrar('waf.blocked', 'WARN', { method: metodo, route: rota, status: 403, reason: 'ip_blocked_by_incident_response' });
    return { status: 403, erro: 'Acesso bloqueado pela equipe de segurança.' };
  }

  // 1) Autenticação: token válido, assinado e dentro da validade
  const { payload, motivo } = await analisarToken(token);
  if (!payload) {
    const nivelMotivo = { expired: 'INFO', key_rotated: 'INFO', revoked: 'WARN' }[motivo] || 'CRITICAL';
    Log.registrar('api.auth.rejected', nivelMotivo,
      { method: metodo, route: rota, reason: motivo, status: 401 });
    return { status: 401, erro: 'Sessão inválida. Entre novamente.' };
  }

  // 2) Rate limit por usuário
  const limite = checarLimite(payload.sub);
  if (limite) return limite;

  // 3) Rotas
  if (metodo === 'GET' && rota === '/v1/me/vehicles') {
    if (payload.role !== 'cliente') return negar(payload, rota, 'perfil_sem_permissao', 403, 'Acesso negado.');
    const lista = VEICULOS_DB.filter(v => v.ownerId === payload.sub).map(veiculoDTO); // filtra pelo dono
    if (!opcoes.silencioso)
      Log.registrar('data.access', 'INFO', { user_id: payload.sub, route: rota, status: 200, records: lista.length });
    return { status: 200, dados: lista };
  }

  const m = rota.match(/^\/v1\/vehicles\/([^/]+)(\/vin)?$/);
  if (metodo === 'GET' && m) {
    const id = m[1];
    const querVin = Boolean(m[2]);
    const rotaModelo = querVin ? '/v1/vehicles/{id}/vin' : '/v1/vehicles/{id}';

    // Validação do parâmetro de rota
    if (!/^v-\d{4}$/.test(id)) {
      Log.registrar('api.input.rejected', 'WARN', { user_id: payload.sub, route: rotaModelo, reason: 'invalid_id_format', status: 400 });
      return { status: 400, erro: 'Identificador inválido.' };
    }
    if (payload.role !== 'cliente') return negar(payload, rotaModelo, 'perfil_sem_permissao', 403, 'Acesso negado.');

    // Autorização por objeto: o veículo precisa pertencer a quem pede.
    // Responde 404 (e não 403) para não confirmar que o veículo existe.
    const v = VEICULOS_DB.find(x => x.id === id);
    if (!v || v.ownerId !== payload.sub) {
      if (v) Log.registrar('api.authz.bola_attempt', 'CRITICAL', {
        user_id: payload.sub, route: rotaModelo, target_resource: id, status: 404, reason: 'resource_owned_by_another_user'
      });
      return { status: 404, erro: 'Veículo não encontrado.' };
    }
    if (querVin) {
      Log.registrar('data.sensitive.read', 'INFO', { user_id: payload.sub, resource: id, field: 'vin', status: 200 });
      return { status: 200, dados: { vin: v.vin } };
    }
    return { status: 200, dados: veiculoDTO(v) };
  }

  const respAgenda = rotasAgendamento(metodo, rota, payload, opcoes); // seção 15
  if (respAgenda) return respAgenda;

  const respGestao = await rotasGestao(metodo, rota, payload, opcoes); // seção 18
  if (respGestao) return respGestao;

  const respPrivacidade = await rotasPrivacidade(metodo, rota, payload, opcoes); // seção 21
  if (respPrivacidade) return respPrivacidade;

  return { status: 404, erro: 'Rota não encontrada.' };
}

/* =========================================================
   12. CACHE LOCAL CIFRADO (AES-256-GCM)
   Simula o armazenamento do aparelho. No app nativo, a chave
   ficaria no Android Keystore / iOS Keychain.
   ========================================================= */
const CacheSeguro = {
  chave: null,
  armazenamento: new Map(), // o que "fica gravado no aparelho": só texto cifrado

  async iniciar() {
    this.chave = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  },

  async gravar(nome, obj) {
    if (!this.chave) await this.iniciar();
    const iv = crypto.getRandomValues(new Uint8Array(12)); // IV novo a cada gravação
    const cifrado = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.chave, enc.encode(JSON.stringify(obj)));
    this.armazenamento.set(nome, { alg: 'AES-256-GCM', iv: b64url(iv), dados: b64url(cifrado), gravado_em: new Date().toISOString() });
    Log.registrar('storage.cache.write', 'INFO', { key: nome, alg: 'AES-256-GCM', bytes: cifrado.byteLength });
    desenharArmazenamento();
  },

  async ler(nome) {
    const e = this.armazenamento.get(nome);
    if (!e || !this.chave) return null;
    try {
      const claro = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlParaBytes(e.iv) }, this.chave, b64urlParaBytes(e.dados));
      return JSON.parse(new TextDecoder().decode(claro));
    } catch {
      // A tag de autenticação do GCM não confere: dado foi alterado. Descarta.
      Log.registrar('storage.cache.integrity_fail', 'CRITICAL', { key: nome, action: 'cache_discarded' });
      this.armazenamento.delete(nome);
      desenharArmazenamento();
      return null;
    }
  },

  adulterar(nome) { // usado só pela simulação de ataque
    const e = this.armazenamento.get(nome);
    if (!e) return false;
    const b = b64urlParaBytes(e.dados);
    b[Math.floor(b.length / 2)] ^= 0x01;
    e.dados = b64url(b);
    Log.registrar('storage.cache.tampered', 'WARN', { key: nome, simulated: true });
    desenharArmazenamento();
    return true;
  },

  limpar() {
    const tinha = this.armazenamento.size > 0;
    this.armazenamento.clear();
    this.chave = null;
    if (tinha) Log.registrar('storage.cache.wiped', 'INFO', { reason: 'session_closed' });
    desenharArmazenamento();
  }
};

function desenharArmazenamento() {
  const alvo = document.getElementById('storageView');
  alvo.innerHTML = '';
  if (!CacheSeguro.armazenamento.size) {
    const p = document.createElement('p');
    p.style.margin = '0';
    p.textContent = 'Nada salvo. O cache é criado quando o cliente entra e apagado quando ele sai.';
    alvo.appendChild(p);
    return;
  }
  CacheSeguro.armazenamento.forEach((e, nome) => {
    const pre = document.createElement('pre');
    pre.textContent = JSON.stringify({ chave: nome, alg: e.alg, iv: e.iv, dados: e.dados.slice(0, 64) + '…', gravado_em: e.gravado_em }, null, 2);
    alvo.appendChild(pre);
  });
}

/* =========================================================
   13. TELA DO CLIENTE: veículo, próxima revisão, garantia, histórico
   ========================================================= */
// Cria elementos com texto seguro (nunca interpreta HTML vindo de dados)
function el(tag, props = {}, ...filhos) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const f of filhos.flat()) {
    if (f === null || f === undefined || f === false) continue;
    n.append(f instanceof Node ? f : document.createTextNode(String(f)));
  }
  return n;
}

const DIA_MS = 86400000;
const dataLocal = iso => new Date(iso + 'T12:00:00');
const fmtData = d => (d instanceof Date ? d : dataLocal(d)).toLocaleDateString('pt-BR');
const fmtKm = n => n.toLocaleString('pt-BR') + ' km';
const plural = (n, um, varios) => `${n} ${n === 1 ? um : varios}`;

function addMeses(iso, meses) {
  const d = dataLocal(iso);
  d.setMonth(d.getMonth() + meses);
  return d;
}

function tempoRelativo(iso) {
  const min = Math.round((Date.now() - new Date(iso)) / 60000);
  if (min < 1) return 'agora há pouco';
  if (min < 60) return `há ${plural(min, 'minuto', 'minutos')}`;
  return `há ${plural(Math.round(min / 60), 'hora', 'horas')}`;
}

function calcularRevisao(v) {
  const baseKm = v.ultima_revisao ? v.ultima_revisao.km : 0;
  const baseData = v.ultima_revisao ? v.ultima_revisao.data : v.entrega;
  const kmAlvo = baseKm + v.plano.intervaloKm;
  const dataAlvo = addMeses(baseData, v.plano.intervaloMeses);
  const kmRestante = kmAlvo - v.km;
  const dias = Math.ceil((dataAlvo - Date.now()) / DIA_MS);
  let status = 'em_dia';
  if (kmRestante <= 0 || dias <= 0) status = 'atrasada';
  else if (kmRestante <= 2000 || dias <= 30) status = 'proxima';
  const progresso = Math.min(1, Math.max(0, (v.km - baseKm) / v.plano.intervaloKm));
  return { baseKm, kmAlvo, dataAlvo, kmRestante, dias, status, progresso };
}

const ROTULO_STATUS = { em_dia: 'Em dia', proxima: 'Próxima', atrasada: 'Atrasada', ativa: 'Ativa', expirada: 'Expirada' };

let veiculoAtivo = null;
let timerVin = null;

function iniciarTimerSessao(payload) {
  const alvo = document.getElementById('kvExpira');
  clearInterval(timerSessao);
  const tick = () => {
    const resta = payload.exp - Math.floor(Date.now() / 1000);
    if (resta <= 0) return encerrarSessao('expirou');
    alvo.textContent = String(Math.floor(resta / 60)).padStart(2, '0') + ':' + String(resta % 60).padStart(2, '0');
    alvo.classList.toggle('low', resta < 60);
  };
  tick();
  timerSessao = setInterval(tick, 1000);
}

async function telaCliente() {
  const payload = await exigirSessao(['cliente']);
  if (!payload) return encerrarSessao('expirou');
  const usuario = USUARIOS.find(u => u.id === payload.sub);

  // Busca na API; se falhar (ex.: 429), usa o cache cifrado do aparelho
  let veiculos = null;
  let doCache = false;
  const r = await api('GET', '/v1/me/vehicles', sessao.token);
  if (r.status === 200) {
    veiculos = r.dados;
    await CacheSeguro.gravar('veiculos', veiculos);
  } else if (r.status === 401) {
    return encerrarSessao('expirou');
  } else {
    veiculos = await CacheSeguro.ler('veiculos');
    doCache = true;
  }

  tela.innerHTML = `
    <div class="topbar">
      <div class="topline">
        <p class="brand">Ford Pós-Venda</p>
        <button class="btn-sair" id="btnSair" type="button">Sair</button>
      </div>
      <h1 id="saudacao"></h1>
      <p class="sessao-linha">Sessão expira em <span class="countdown" id="kvExpira"></span></p>
    </div>
    <div class="body" id="corpo"></div>`;
  document.getElementById('saudacao').textContent = `Olá, ${usuario.nome.split(' ')[0]}`;
  document.getElementById('btnSair').addEventListener('click', () => encerrarSessao('logout'));
  iniciarTimerSessao(payload);

  if (!veiculos) {
    document.getElementById('corpo').append(
      el('div', { class: 'alert alert-error' }, 'Não foi possível carregar seus veículos. Verifique a conexão e tente novamente.'));
    return;
  }
  if (!veiculoAtivo || !veiculos.some(v => v.id === veiculoAtivo)) veiculoAtivo = veiculos[0] ? veiculos[0].id : null;
  desenharCliente(veiculos, doCache);
}

function desenharCliente(veiculos, doCache) {
  const corpo = document.getElementById('corpo');
  corpo.innerHTML = '';
  clearTimeout(timerVin);

  if (doCache) corpo.append(el('div', { class: 'banner' }, 'Mostrando os dados salvos no aparelho. Eles serão atualizados quando a conexão voltar.'));

  if (!veiculos.length) {
    corpo.append(el('div', { class: 'card' },
      el('h2', {}, 'Nenhum veículo vinculado'),
      el('p', { class: 'muted' }, 'Cadastre seu Ford pelo VIN ou pela placa para acompanhar revisões e garantia.')));
    return;
  }

  if (veiculos.length > 1) {
    corpo.append(el('div', { class: 'chips', role: 'group', 'aria-label': 'Escolha o veículo' },
      veiculos.map(v => el('button', {
        type: 'button', class: 'chip', 'aria-pressed': String(v.id === veiculoAtivo),
        onclick: () => { veiculoAtivo = v.id; desenharCliente(veiculos, doCache); }
      }, v.modelo))));
  }

  const v = veiculos.find(x => x.id === veiculoAtivo);
  corpo.append(cardVeiculo(v), cardRevisao(v), cardGarantia(v), cardHistorico(v), cardPrivacidade());
}

function cardVeiculo(v) {
  const ddVin = el('dd', {}, v.vin_mascarado);
  const btnVin = el('button', { type: 'button', 'aria-label': 'Mostrar o VIN completo' }, 'Mostrar');

  const fecharVin = () => {
    clearTimeout(timerVin);
    ddVin.textContent = v.vin_mascarado;
    btnVin.textContent = 'Mostrar';
    btnVin.dataset.aberto = '';
  };
  btnVin.addEventListener('click', async () => {
    if (btnVin.dataset.aberto) return fecharVin();
    const r = await api('GET', `/v1/vehicles/${v.id}/vin`, sessao.token);
    if (r.status === 401) return encerrarSessao('expirou');
    if (r.status !== 200) {
      btnVin.textContent = r.status === 429 ? 'Aguarde' : 'Indisponível';
      setTimeout(() => (btnVin.textContent = 'Mostrar'), 2000);
      return;
    }
    ddVin.textContent = r.dados.vin;
    btnVin.textContent = 'Ocultar';
    btnVin.dataset.aberto = '1';
    timerVin = setTimeout(fecharVin, 15000); // volta a mascarar sozinho
  });

  return el('section', { class: 'veiculo', 'aria-label': 'Seu veículo' },
    el('p', { class: 'modelo' }, v.modelo),
    el('p', { class: 'versao' }, `${v.versao}, ${v.ano}`),
    el('dl', {},
      el('div', {}, el('dt', {}, 'Placa'), el('dd', {}, v.placa)),
      el('div', {}, el('dt', {}, 'Quilometragem'), el('dd', {}, fmtKm(v.km))),
      el('div', {}, el('dt', {}, 'Entregue em'), el('dd', {}, fmtData(v.entrega))),
      el('div', {}, el('dt', {}, 'Revisões na rede'), el('dd', {}, String(v.historico.length))),
      el('div', { class: 'vin' }, el('div', {}, el('dt', {}, 'VIN (chassi)'), ddVin), btnVin)
    ),
    el('p', { class: 'telemetria' }, v.telemetria_em
      ? `Quilometragem enviada pelo veículo conectado ${tempoRelativo(v.telemetria_em)}.`
      : 'Telemetria desligada em Privacidade. A quilometragem é a da última atualização.')
  );
}

function cardRevisao(v) {
  const rev = calcularRevisao(v);
  const ag = v.agendamento_ativo;
  let texto;
  if (rev.status === 'atrasada') {
    texto = rev.dias <= 0
      ? `O prazo venceu em ${fmtData(rev.dataAlvo)}. Agende para manter o plano de manutenção em dia.`
      : `A quilometragem de ${fmtKm(rev.kmAlvo)} já foi atingida. Agende para manter o plano de manutenção em dia.`;
  } else {
    texto = `Faltam ${fmtKm(rev.kmRestante)} ou ${plural(rev.dias, 'dia', 'dias')}, o que vier primeiro.`;
  }
  return el('section', { class: 'card' },
    el('div', { class: 'card-head' },
      el('h2', {}, 'Próxima revisão'),
      ag ? el('span', { class: 'pill agendada' }, 'Agendada')
         : el('span', { class: 'pill ' + rev.status }, ROTULO_STATUS[rev.status])),
    el('p', { class: 'rev-titulo' }, `Revisão dos ${fmtKm(rev.kmAlvo)}`),
    el('div', { class: 'barra ' + rev.status, role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100',
      'aria-valuenow': String(Math.round(rev.progresso * 100)), 'aria-label': 'Quilometragem até a revisão' },
      el('span', { style: `width:${Math.round(rev.progresso * 100)}%` })),
    el('div', { class: 'barra-legenda' }, el('span', {}, fmtKm(rev.baseKm)), el('span', {}, fmtKm(rev.kmAlvo))),
    el('p', { class: 'linha' }, texto),
    ag ? blocoAgendado(ag)
       : el('button', { type: 'button', class: 'btn btn-primary btn-full', onclick: () => telaAgendar(v.id) }, 'Agendar revisão')
  );
}

function cardGarantia(v) {
  const fim = dataLocal(v.garantia_fim);
  const dias = Math.ceil((fim - Date.now()) / DIA_MS);
  const ativa = dias > 0;
  const meses = Math.floor(dias / 30.44);
  const texto = ativa
    ? `Garantia de fábrica válida até ${fmtData(fim)}. ${meses >= 1 ? 'Restam ' + plural(meses, 'mês', 'meses') + '.' : 'Restam ' + plural(dias, 'dia', 'dias') + '.'}`
    : `A garantia de fábrica terminou em ${fmtData(fim)}.`;
  return el('section', { class: 'card' },
    el('div', { class: 'card-head' },
      el('h2', {}, 'Garantia'),
      el('span', { class: 'pill ' + (ativa ? 'ativa' : 'expirada') }, ROTULO_STATUS[ativa ? 'ativa' : 'expirada'])),
    el('p', { class: 'linha', style: 'margin:0' }, texto));
}

function cardHistorico(v) {
  const corpo = v.historico.length
    ? el('ol', { class: 'historico' }, v.historico.map(h =>
        el('li', {},
          el('span', { class: 'data' }, fmtData(h.data)),
          el('span', {}, h.servico),
          el('span', { class: 'local' }, h.local))))
    : el('p', { class: 'muted' }, 'Nenhum serviço registrado na rede Ford ainda. A primeira revisão aparece aqui depois de feita.');
  return el('section', { class: 'card' }, el('h2', {}, 'Histórico de serviços'), corpo);
}

/* =========================================================
   14. DADOS DE AGENDAMENTO (concessionárias, serviços, horários)
   ========================================================= */
const CONCESSIONARIAS = [
  { id:'c-101', nome:'Concessionária Via Norte', endereco:'Av. Cruzeiro do Sul, 2100, Santana, São Paulo' },
  { id:'c-102', nome:'Paulista Motors',          endereco:'Rua Treze de Maio, 850, Bela Vista, São Paulo' },
  { id:'c-103', nome:'Sul Autos',                endereco:'Av. Santo Amaro, 5400, Santo Amaro, São Paulo' }
];

// Listas fechadas (enums): a API só aceita estes valores
const SERVICOS = {
  revisao:     'Revisão programada',
  diagnostico: 'Diagnóstico de problema',
  garantia:    'Atendimento em garantia'
};
const HORARIOS = ['08:00', '09:00', '10:00', '11:00', '13:00', '14:00', '15:00', '16:00'];
const DIAS_JANELA = 10;   // dias úteis disponíveis para agendar, a partir de amanhã
const OBS_MAX = 280;
// Observações: letras (com acento), números, espaço e pontuação comum. Sem < > { } [ ] ` $ \
const REGEX_OBS = /^[\p{L}\p{N}\s.,;:!?()\-\/'"%ºª°]*$/u;

const AGENDAMENTOS_DB = [];   // agendamentos criados (viram leads para o Analista na Parte 4)
const IDEMPOTENCIA = new Map(); // Idempotency-Key -> { userId, corpo, resposta }
let seqProtocolo = 0;

function isoLocal(d) {
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

function diasDisponiveis() {
  const dias = [];
  const d = new Date();
  d.setHours(12, 0, 0, 0);
  while (dias.length < DIAS_JANELA) {
    d.setDate(d.getDate() + 1);
    if (d.getDay() !== 0 && d.getDay() !== 6) dias.push(isoLocal(d));
  }
  return dias;
}

// Ocupação simulada da oficina (determinística) + agendamentos reais
function hashSimples(s) {
  let h = 0;
  for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return h;
}
function horarioLivre(concId, data, hora) {
  if (hashSimples(concId + data + hora) % 3 === 0) return false;
  return !AGENDAMENTOS_DB.some(a => a.status === 'confirmado' && a.concessionariaId === concId && a.data === data && a.hora === hora);
}

function agendamentoAtivo(veiculoId) {
  return AGENDAMENTOS_DB.find(a => a.veiculoId === veiculoId && a.status === 'confirmado') || null;
}

function agendamentoDTO(a) {
  const c = CONCESSIONARIAS.find(x => x.id === a.concessionariaId);
  return {
    id: a.id, protocolo: a.protocolo, veiculo_id: a.veiculoId,
    servico: a.servico, servico_nome: SERVICOS[a.servico],
    concessionaria: c ? { id: c.id, nome: c.nome, endereco: c.endereco } : null,
    data: a.data, hora: a.hora, observacoes: a.observacoes, status: a.status
  };
}

/* =========================================================
   15. API DE AGENDAMENTO (validação estrita + idempotência)
   ========================================================= */
const CAMPOS_AGENDAMENTO = ['veiculo_id', 'servico', 'concessionaria_id', 'data', 'hora', 'observacoes'];
const REGEX_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

// Validação de esquema: rejeita campo extra, valor fora da lista e texto com caracteres perigosos
function validarAgendamento(c) {
  if (!c || typeof c !== 'object' || Array.isArray(c))
    return { campo: 'body', motivo: 'invalid_body', msg: 'Dados do agendamento inválidos.' };
  const extras = Object.keys(c).filter(k => !CAMPOS_AGENDAMENTO.includes(k));
  if (extras.length)
    return { campo: extras.join(','), motivo: 'unexpected_fields', msg: 'O pedido tem campos não permitidos.' };
  if (typeof c.veiculo_id !== 'string' || !/^v-\d{4}$/.test(c.veiculo_id))
    return { campo: 'veiculo_id', motivo: 'invalid_format', msg: 'Veículo inválido.' };
  if (!Object.hasOwn(SERVICOS, c.servico))
    return { campo: 'servico', motivo: 'not_in_enum', msg: 'Escolha um tipo de serviço.' };
  if (!CONCESSIONARIAS.some(x => x.id === c.concessionaria_id))
    return { campo: 'concessionaria_id', motivo: 'not_in_enum', msg: 'Escolha uma concessionária.' };
  if (!diasDisponiveis().includes(c.data))
    return { campo: 'data', motivo: 'out_of_window', msg: 'Escolha uma das datas disponíveis.' };
  if (!HORARIOS.includes(c.hora))
    return { campo: 'hora', motivo: 'not_in_enum', msg: 'Escolha um horário.' };
  const obs = c.observacoes === undefined ? '' : c.observacoes;
  if (typeof obs !== 'string' || obs.length > OBS_MAX)
    return { campo: 'observacoes', motivo: 'too_long', msg: `As observações têm até ${OBS_MAX} caracteres.` };
  if (!REGEX_OBS.test(obs))
    return { campo: 'observacoes', motivo: 'disallowed_characters', msg: 'As observações aceitam letras, números e pontuação comum.' };
  return null;
}

function rotasAgendamento(metodo, rota, payload, opcoes) {
  let m;
  if (metodo === 'GET' && rota === '/v1/dealers') {
    return listarConcessionarias(payload, opcoes.query && opcoes.query.veiculo_id); // seção 21
  }
  if (metodo === 'GET' && (m = rota.match(/^\/v1\/dealers\/([^/]+)\/slots$/))) {
    const data = opcoes.query && opcoes.query.data;
    if (!CONCESSIONARIAS.some(c => c.id === m[1]) || !diasDisponiveis().includes(data)) {
      Log.registrar('api.input.rejected', 'WARN', { user_id: payload.sub, route: '/v1/dealers/{id}/slots', reason: 'invalid_params', status: 400 });
      return { status: 400, erro: 'Parâmetros inválidos.' };
    }
    return { status: 200, dados: HORARIOS.map(h => ({ hora: h, livre: horarioLivre(m[1], data, h) })) };
  }
  if (metodo === 'POST' && rota === '/v1/appointments') return criarAgendamento(payload, opcoes);
  if (metodo === 'DELETE' && (m = rota.match(/^\/v1\/appointments\/([^/]+)$/))) return cancelarAgendamento(payload, m[1]);
  return null;
}

// Importante: não há "await" dentro desta função. A checagem e a gravação da
// chave de idempotência acontecem juntas, então dois envios simultâneos não criam dois registros.
function criarAgendamento(payload, opcoes) {
  const rota = '/v1/appointments';
  if (payload.role !== 'cliente') return negar(payload, rota, 'perfil_sem_permissao', 403, 'Acesso negado.');

  // 1) Chave de idempotência obrigatória (UUID v4)
  const chave = opcoes.idempotencyKey;
  if (!chave || !REGEX_UUID.test(chave)) {
    Log.registrar('api.input.rejected', 'WARN', { user_id: payload.sub, route: rota, reason: 'missing_idempotency_key', status: 400 });
    return { status: 400, erro: 'Pedido sem chave de idempotência.' };
  }
  const corpo = opcoes.corpo;
  const corpoCanonico = JSON.stringify(corpo, corpo && typeof corpo === 'object' ? Object.keys(corpo).sort() : undefined);

  // 2) Chave já usada: mesmo pedido devolve a mesma resposta; pedido diferente é recusado
  const salvo = IDEMPOTENCIA.get(chave);
  if (salvo) {
    if (salvo.userId !== payload.sub || salvo.corpo !== corpoCanonico) {
      Log.registrar('api.idempotency.key_reuse', 'WARN', { user_id: payload.sub, route: rota, status: 422 });
      return { status: 422, erro: 'Esta chave já foi usada em outro pedido.' };
    }
    Log.registrar('api.idempotency.replay', 'INFO', { user_id: payload.sub, route: rota, status: salvo.resposta.status, duplicate_prevented: true });
    return { ...salvo.resposta, replay: true };
  }

  // 3) Validação de esquema
  const erro = validarAgendamento(corpo);
  if (erro) {
    Log.registrar('api.input.rejected', 'WARN', { user_id: payload.sub, route: rota, field: erro.campo, reason: erro.motivo, status: 400 });
    return { status: 400, erro: erro.msg, campo: erro.campo };
  }

  // 4) Autorização por objeto: o veículo precisa ser de quem está agendando
  const v = VEICULOS_DB.find(x => x.id === corpo.veiculo_id);
  if (!v || v.ownerId !== payload.sub) {
    if (v) Log.registrar('api.authz.bola_attempt', 'CRITICAL', { user_id: payload.sub, route: rota, target_resource: v.id, status: 404, reason: 'resource_owned_by_another_user' });
    return { status: 404, erro: 'Veículo não encontrado.' };
  }

  // 5) Regras de negócio
  let resposta;
  if (agendamentoAtivo(v.id)) {
    resposta = { status: 409, erro: 'Este veículo já tem um agendamento confirmado.' };
  } else if (!horarioLivre(corpo.concessionaria_id, corpo.data, corpo.hora)) {
    resposta = { status: 409, erro: 'Esse horário acabou de ser ocupado. Escolha outro.' };
  } else {
    seqProtocolo += 1;
    const a = {
      id: 'a-' + String(7000 + seqProtocolo),
      protocolo: `AGD-${new Date().getFullYear()}-${String(seqProtocolo).padStart(5, '0')}`,
      ownerId: payload.sub, veiculoId: v.id, servico: corpo.servico,
      concessionariaId: corpo.concessionaria_id, data: corpo.data, hora: corpo.hora,
      observacoes: (corpo.observacoes || '').trim(), status: 'confirmado', criadoEm: new Date().toISOString()
    };
    AGENDAMENTOS_DB.push(a);
    // O texto das observações não vai para o log (pode conter dado pessoal)
    Log.registrar('appointment.created', 'INFO', { user_id: payload.sub, appointment_id: a.id, vehicle_id: v.id, dealer_id: a.concessionariaId, service: a.servico, status: 201 });
    resposta = { status: 201, dados: agendamentoDTO(a) };
  }
  if (resposta.status === 409)
    Log.registrar('appointment.conflict', 'WARN', { user_id: payload.sub, vehicle_id: v.id, status: 409 });

  IDEMPOTENCIA.set(chave, { userId: payload.sub, corpo: corpoCanonico, resposta });
  return resposta;
}

function cancelarAgendamento(payload, id) {
  const rota = '/v1/appointments/{id}';
  if (payload.role !== 'cliente') return negar(payload, rota, 'perfil_sem_permissao', 403, 'Acesso negado.');
  if (!/^a-\d{4}$/.test(id)) {
    Log.registrar('api.input.rejected', 'WARN', { user_id: payload.sub, route: rota, reason: 'invalid_id_format', status: 400 });
    return { status: 400, erro: 'Identificador inválido.' };
  }
  const a = AGENDAMENTOS_DB.find(x => x.id === id);
  if (!a || a.ownerId !== payload.sub) {
    if (a) Log.registrar('api.authz.bola_attempt', 'CRITICAL', { user_id: payload.sub, route: rota, target_resource: id, status: 404, reason: 'resource_owned_by_another_user' });
    return { status: 404, erro: 'Agendamento não encontrado.' };
  }
  if (a.status !== 'confirmado') return { status: 409, erro: 'Este agendamento já foi cancelado.' };
  a.status = 'cancelado';
  a.canceladoEm = new Date().toISOString();
  Log.registrar('appointment.cancelled', 'INFO', { user_id: payload.sub, appointment_id: id, status: 200 });
  return { status: 200, dados: agendamentoDTO(a) };
}

/* =========================================================
   16. TELAS DE AGENDAMENTO (formulário, confirmação, cancelamento)
   ========================================================= */
const primeiraMaiuscula = t => t.charAt(0).toUpperCase() + t.slice(1);
const fmtDiaSemana = iso => primeiraMaiuscula(dataLocal(iso).toLocaleDateString('pt-BR', { weekday: 'long', day: '2-digit', month: '2-digit' }));

function blocoAgendado(ag) {
  const msg = el('p', { class: 'nota', role: 'status' });
  const btn = el('button', { type: 'button', class: 'btn btn-ghost btn-full' }, 'Cancelar agendamento');
  let armado = false;
  let t = null;
  btn.addEventListener('click', async () => {
    if (!armado) { // confirmação em dois toques
      armado = true;
      btn.textContent = 'Toque de novo para cancelar';
      t = setTimeout(() => { armado = false; btn.textContent = 'Cancelar agendamento'; }, 4000);
      return;
    }
    clearTimeout(t);
    btn.disabled = true;
    const r = await api('DELETE', `/v1/appointments/${ag.id}`, sessao.token);
    if (r.status === 401) return encerrarSessao('expirou');
    if (r.status === 200) return telaCliente();
    btn.disabled = false;
    armado = false;
    btn.textContent = 'Cancelar agendamento';
    msg.textContent = r.erro;
  });
  return el('div', { class: 'agendado' },
    el('p', { class: 'agendado-quando' }, `${fmtDiaSemana(ag.data)} às ${ag.hora}`),
    el('p', { class: 'agendado-onde' }, `${ag.servico_nome} na ${ag.concessionaria.nome}. Protocolo ${ag.protocolo}.`),
    btn, msg);
}

function cabecalhoInterno(titulo, subtitulo, aoVoltar) {
  tela.innerHTML = `
    <div class="topbar">
      <div class="topline">
        <button class="btn-sair" id="btnVoltar" type="button">Voltar</button>
        <span class="sessao-linha" style="margin:0">Sessão <span class="countdown" id="kvExpira"></span></span>
      </div>
      <h1 id="tituloTela"></h1>
      <p class="sessao-linha" id="subTela"></p>
    </div>
    <div id="corpo"></div>`;
  document.getElementById('tituloTela').textContent = titulo;
  document.getElementById('subTela').textContent = subtitulo;
  const voltar = document.getElementById('btnVoltar');
  if (aoVoltar) voltar.addEventListener('click', aoVoltar);
  else voltar.remove();
}

async function telaAgendar(veiculoId) {
  const payload = await exigirSessao(['cliente']);
  if (!payload) return encerrarSessao('expirou');

  const rv = await api('GET', `/v1/vehicles/${veiculoId}`, sessao.token);
  if (rv.status === 401) return encerrarSessao('expirou');
  if (rv.status !== 200) return telaCliente();
  const rd = await api('GET', '/v1/dealers', sessao.token, { query: { veiculo_id: veiculoId } });
  const v = rv.dados;
  const rev = calcularRevisao(v);
  const garantiaAtiva = dataLocal(v.garantia_fim) > new Date();

  cabecalhoInterno('Agendar serviço', `${v.modelo} ${v.versao}, ${v.ano}`, () => telaCliente());
  iniciarTimerSessao(payload);
  const corpo = document.getElementById('corpo');

  if (rd.status !== 200) {
    corpo.append(el('div', { class: 'body' }, el('div', { class: 'alert alert-error' }, rd.erro || 'Não foi possível carregar as concessionárias.')));
    return;
  }

  // Estado do formulário. A chave de idempotência nasce junto com o formulário
  // e só é trocada quando o servidor dá uma resposta final de erro.
  const dias = diasDisponiveis();
  const ultimaConc = v.historico[0] ? rd.dados.find(c => v.historico[0].local.startsWith(c.nome)) : null;
  const estado = { servico: 'revisao', concessionaria_id: ultimaConc ? ultimaConc.id : null, data: dias[0], hora: null, observacoes: '' };
  let chaveIdem = crypto.randomUUID();

  const form = el('form', { class: 'form-ag', novalidate: '' });
  const msg = el('div', { role: 'alert' });

  // --- Serviço
  const opcoesServico = [
    { id: 'revisao', titulo: `Revisão dos ${fmtKm(rev.kmAlvo)}`, desc: 'Itens do plano de manutenção do fabricante', tag: rev.status !== 'em_dia' ? 'Recomendada agora' : null },
    { id: 'diagnostico', titulo: SERVICOS.diagnostico, desc: 'Barulho, luz acesa no painel ou falha' },
    { id: 'garantia', titulo: SERVICOS.garantia, desc: garantiaAtiva ? 'Defeitos cobertos pela garantia de fábrica' : 'A garantia deste veículo terminou', desabilitado: !garantiaAtiva }
  ];
  form.append(el('fieldset', { class: 'grupo' }, el('legend', {}, 'Serviço'),
    opcoesServico.map(o => {
      const input = el('input', { type: 'radio', name: 'servico', value: o.id });
      input.checked = estado.servico === o.id;
      input.disabled = Boolean(o.desabilitado);
      input.addEventListener('change', () => { estado.servico = o.id; });
      return el('label', { class: 'opcao' }, input,
        el('div', {}, el('strong', {}, o.titulo, o.tag ? el('span', { class: 'tag' }, o.tag) : null), el('span', {}, o.desc)));
    })));

  // --- Concessionária
  form.append(el('fieldset', { class: 'grupo' }, el('legend', {}, 'Concessionária'),
    rd.localizacao_usada ? null : el('p', { class: 'vazio' }, 'Ative a localização em Privacidade para ver a concessionária mais próxima do veículo.'),
    rd.dados.map((c, i) => {
      const input = el('input', { type: 'radio', name: 'concessionaria', value: c.id });
      input.checked = estado.concessionaria_id === c.id;
      input.addEventListener('change', () => { estado.concessionaria_id = c.id; estado.hora = null; carregarHorarios(); });
      const dist = c.distancia_km !== undefined ? ` A ${c.distancia_km.toLocaleString('pt-BR')} km do veículo.` : '';
      return el('label', { class: 'opcao' }, input, el('div', {},
        el('strong', {}, c.nome, i === 0 && dist ? el('span', { class: 'tag' }, 'Mais perto') : null),
        el('span', {}, c.endereco + '.' + dist)));
    })));

  // --- Data
  const boxDias = el('div', { class: 'dias', role: 'group', 'aria-label': 'Datas disponíveis' });
  const desenharDias = () => {
    boxDias.innerHTML = '';
    dias.forEach(d => {
      const dt = dataLocal(d);
      boxDias.append(el('button', {
        type: 'button', class: 'dia', 'aria-pressed': String(d === estado.data), 'aria-label': fmtDiaSemana(d),
        onclick: () => { estado.data = d; estado.hora = null; desenharDias(); carregarHorarios(); }
      }, el('small', {}, dt.toLocaleDateString('pt-BR', { weekday: 'short' }).replace('.', '')),
         el('b', {}, dt.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' }))));
    });
  };
  form.append(el('fieldset', { class: 'grupo' }, el('legend', {}, 'Data'), boxDias));

  // --- Horário (vem da API)
  const boxHoras = el('div', {});
  async function carregarHorarios() {
    boxHoras.innerHTML = '';
    if (!estado.concessionaria_id) {
      boxHoras.append(el('p', { class: 'vazio' }, 'Escolha a concessionária para ver os horários.'));
      return;
    }
    const r = await api('GET', `/v1/dealers/${estado.concessionaria_id}/slots`, sessao.token, { query: { data: estado.data } });
    boxHoras.innerHTML = '';
    if (r.status === 401) return encerrarSessao('expirou');
    if (r.status !== 200) {
      boxHoras.append(el('p', { class: 'vazio' }, r.status === 429 ? 'Muitas consultas seguidas. Aguarde um instante e escolha a data de novo.' : r.erro));
      return;
    }
    if (!r.dados.some(h => h.livre)) {
      boxHoras.append(el('p', { class: 'vazio' }, 'Sem horários livres nesta data. Escolha outro dia.'));
      return;
    }
    const grade = el('div', { class: 'horas', role: 'group', 'aria-label': 'Horários' });
    r.dados.forEach(h => {
      const b = el('button', { type: 'button', class: 'hora', 'aria-pressed': String(h.hora === estado.hora) }, h.hora);
      b.disabled = !h.livre;
      if (!h.livre) b.setAttribute('aria-label', `${h.hora}, ocupado`);
      b.addEventListener('click', () => {
        estado.hora = h.hora;
        grade.querySelectorAll('.hora').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
      });
      grade.append(b);
    });
    boxHoras.append(grade);
  }
  form.append(el('fieldset', { class: 'grupo' }, el('legend', {}, 'Horário'), boxHoras));

  // --- Observações
  const txt = el('textarea', { class: 'obs', id: 'obs', maxlength: String(OBS_MAX), rows: '3', 'aria-describedby': 'obsInfo',
    placeholder: 'Ex.: barulho na suspensão dianteira ao passar em lombadas' });
  const contador = el('span', {}, `0/${OBS_MAX}`);
  const erroObs = el('span', { class: 'erro' });
  txt.addEventListener('input', () => {
    estado.observacoes = txt.value;
    contador.textContent = `${txt.value.length}/${OBS_MAX}`;
    const ok = REGEX_OBS.test(txt.value);
    txt.setAttribute('aria-invalid', String(!ok));
    erroObs.textContent = ok ? '' : 'Use apenas letras, números e pontuação comum.';
  });
  form.append(el('div', { class: 'grupo' },
    el('label', { for: 'obs', style: 'font-size:16px;font-weight:800' }, 'Observações (opcional)'),
    txt, el('div', { class: 'contador', id: 'obsInfo' }, erroObs, contador)));

  // --- Envio
  const btn = el('button', { class: 'btn btn-primary', type: 'submit' }, 'Confirmar agendamento');
  form.append(msg, btn);

  form.addEventListener('submit', async ev => {
    ev.preventDefault();
    msg.innerHTML = '';
    const faltando = [];
    if (!estado.concessionaria_id) faltando.push('a concessionária');
    if (!estado.hora) faltando.push('o horário');
    if (faltando.length) {
      msg.append(el('div', { class: 'alert alert-error' }, `Escolha ${faltando.join(' e ')} para continuar.`));
      return;
    }
    if (!REGEX_OBS.test(estado.observacoes)) {
      msg.append(el('div', { class: 'alert alert-error' }, 'Revise as observações: use apenas letras, números e pontuação comum.'));
      txt.focus();
      return;
    }

    btn.disabled = true; // primeira barreira contra clique duplo (a segunda é a chave de idempotência)
    btn.textContent = 'Confirmando...';
    const corpoPedido = {
      veiculo_id: v.id, servico: estado.servico, concessionaria_id: estado.concessionaria_id,
      data: estado.data, hora: estado.hora, observacoes: estado.observacoes.trim()
    };
    const r = await api('POST', '/v1/appointments', sessao.token, { corpo: corpoPedido, idempotencyKey: chaveIdem });

    if (r.status === 401) return encerrarSessao('expirou');
    if (r.status === 201) return telaConfirmacao(r.dados, v);

    chaveIdem = crypto.randomUUID(); // resposta final de erro: próximo envio é um pedido novo
    btn.disabled = false;
    btn.textContent = 'Confirmar agendamento';
    msg.append(el('div', { class: 'alert alert-error' }, r.erro || 'Não foi possível agendar. Tente novamente.'));
    if (r.status === 409) { estado.hora = null; carregarHorarios(); }
  });

  corpo.append(form);
  desenharDias();
  carregarHorarios();
}

function telaConfirmacao(a, v) {
  cabecalhoInterno('Agendamento confirmado', `${v.modelo} ${v.versao}, ${v.ano}`, null);
  exigirSessao(['cliente']).then(p => p && iniciarTimerSessao(p));
  const corpo = document.getElementById('corpo');

  const itens = [
    ['Serviço', a.servico_nome],
    ['Data e horário', `${fmtDiaSemana(a.data)} às ${a.hora}`],
    ['Concessionária', el('span', {}, a.concessionaria.nome, el('small', {}, a.concessionaria.endereco))]
  ];
  if (a.observacoes) itens.push(['Observações', a.observacoes]);

  corpo.append(el('div', { class: 'body' },
    el('section', { class: 'confirmado', 'aria-label': 'Protocolo' },
      el('p', { class: 'rot' }, 'Protocolo'),
      el('p', { class: 'protocolo' }, a.protocolo)),
    el('section', { class: 'card' },
      el('dl', { class: 'detalhes' }, itens.map(([k, val]) => el('div', {}, el('dt', {}, k), el('dd', {}, val))))),
    el('p', { class: 'muted' }, 'Leve o documento do veículo. Para mudar a data, cancele pelo app e agende de novo.'),
    el('button', { type: 'button', class: 'btn btn-primary', onclick: () => telaCliente() }, 'Voltar ao início')));
}

/* =========================================================
   17. SIMULAÇÕES DE ATAQUE (painel de desenvolvimento)
   ========================================================= */
// Cada botão declara em data-perfis quais perfis podem executá-lo
function ativarSimulacoes(perfil) {
  document.querySelectorAll('[data-sim]').forEach(b => {
    b.disabled = !perfil || !b.dataset.perfis.split(' ').includes(perfil);
  });
  if (!perfil) resultadoSim('');
}
function resultadoSim(t) { document.getElementById('simResult').textContent = t; }

const SIMULACOES = {
  // IDOR/BOLA: pede o veículo de outro cliente trocando o id na URL
  async idor() {
    const r = await api('GET', '/v1/vehicles/v-5099', sessao.token);
    return `GET /v1/vehicles/v-5099 → ${r.status} ${r.erro || ''}`;
  },
  // Troca role para admin no payload, mantendo a assinatura original
  async token() {
    const [h, p, s] = sessao.token.split('.');
    const payload = JSON.parse(new TextDecoder().decode(b64urlParaBytes(p)));
    payload.role = 'admin';
    const falso = h + '.' + b64urlJson(payload) + '.' + s;
    const r = await api('GET', '/v1/admin/users', falso);
    return `Token com role=admin e assinatura original → GET /v1/admin/users → ${r.status} ${r.erro || ''}`;
  },
  // Flood: 35 requisições seguidas contra o limite de 30 por minuto
  async flood() {
    const cont = {};
    for (let i = 0; i < 35; i++) {
      const r = await api('GET', '/v1/me/vehicles', sessao.token, { silencioso: true });
      cont[r.status] = (cont[r.status] || 0) + 1;
    }
    return '35 requisições → ' + Object.entries(cont).map(([st, n]) => `${n}× ${st}`).join(', ');
  },
  // Altera 1 byte do cache cifrado e tenta ler
  async cache() {
    if (!CacheSeguro.adulterar('veiculos')) return 'Nenhum cache para adulterar. Entre como cliente primeiro.';
    const lido = await CacheSeguro.ler('veiculos');
    return lido ? 'Cache lido sem erro (inesperado).' : '1 byte alterado → AES-GCM recusou a leitura (tag inválida). Cache descartado.';
  },
  // Clique duplo: dois POST simultâneos com a MESMA chave de idempotência
  async duplo() {
    const p = await verificarToken(sessao.token);
    const alvo = VEICULOS_DB.find(v => v.ownerId === p.sub && !agendamentoAtivo(v.id));
    if (!alvo) return 'Os dois veículos já têm agendamento. Cancele um deles para repetir o teste.';
    const corpo = corpoValidoPara(alvo.id);
    if (!corpo) return 'Nenhum horário livre encontrado.';
    const chave = crypto.randomUUID();
    const [r1, r2] = await Promise.all([
      api('POST', '/v1/appointments', sessao.token, { corpo, idempotencyKey: chave }),
      api('POST', '/v1/appointments', sessao.token, { corpo, idempotencyKey: chave })
    ]);
    const criados = AGENDAMENTOS_DB.filter(a => a.veiculoId === alvo.id && a.status === 'confirmado').length;
    await atualizarInicioSeAberto();
    const d = r => `${r.status}${r.replay ? ' (replay)' : ''} ${r.dados ? r.dados.protocolo : r.erro}`;
    return `2 envios, mesma chave → [${d(r1)}] e [${d(r2)}]. Agendamentos criados para a ${alvo.modelo}: ${criados}.`;
  },
  // XSS armazenado: tenta gravar HTML/JS nas observações
  async xss() {
    const corpo = { ...corpoValidoPara('v-5001'), observacoes: '<img src=x onerror=alert(document.cookie)>' };
    const r = await api('POST', '/v1/appointments', sessao.token, { corpo, idempotencyKey: crypto.randomUUID() });
    return `observacoes = <img onerror=...> → ${r.status} ${r.erro || ''}`;
  },
  // Mass assignment: envia campos que o cliente não pode definir
  async extras() {
    const corpo = { ...corpoValidoPara('v-5001'), status: 'concluido', preco: 0 };
    const r = await api('POST', '/v1/appointments', sessao.token, { corpo, idempotencyKey: crypto.randomUUID() });
    return `Pedido com status="concluido" e preco=0 → ${r.status} ${r.erro || ''}`;
  },
  // Escalonamento de privilégio: cada perfil tenta uma rota que não é dele
  async escalada() {
    const p = await verificarToken(sessao.token);
    const alvo = {
      cliente:  ['GET', '/v1/analytics/leads', {}],
      analista: ['PATCH', '/v1/admin/users/u-2001', { corpo: { perfil: 'admin' } }], // tenta se promover
      admin:    ['GET', '/v1/analytics/leads', {}]                                  // menor privilégio: admin não vê leads
    }[p.role];
    const r = await api(alvo[0], alvo[1], sessao.token, alvo[2]);
    return `${PERFIS[p.role].rotulo} → ${alvo[0]} ${alvo[1]} → ${r.status} ${r.erro || ''}`;
  },
  // Revogação: a cliente tem um token válido; o admin encerra as sessões dela; o mesmo token deixa de valer
  async revogar() {
    const cliente = USUARIOS.find(u => u.id === 'u-1001');
    const tokenCliente = await emitirToken(cliente); // representa a sessão aberta no celular da cliente
    const antes = await api('GET', '/v1/me/vehicles', tokenCliente, { silencioso: true });
    const acao = await api('POST', '/v1/admin/users/u-1001/revoke-sessions', sessao.token);
    const depois = await api('GET', '/v1/me/vehicles', tokenCliente);
    return `Token da cliente antes: ${antes.status}. Admin encerra sessões: ${acao.status}. Mesmo token depois: ${depois.status} (revogado).`;
  },
  // Tenta exportar os dados de outro titular passando um id na URL
  async exportar() {
    const r = await api('GET', '/v1/me/data-export', sessao.token, { query: { user_id: 'u-1002' } });
    return `GET /v1/me/data-export?user_id=u-1002 → ${r.status}, titular devolvido: ${r.dados ? r.dados.titular.id : '-'} (o id vem só do token; o parâmetro é ignorado e registrado)`;
  },
  // Pedido de exclusão sem saber a senha (ex.: celular desbloqueado na mão de outra pessoa)
  async reauth() {
    // Triagem Semgrep: FALSO POSITIVO. Senha propositalmente errada usada pela simulação de ataque.
    const r = await api('POST', '/v1/me/deletion', sessao.token, { corpo: { senha: 'SenhaErrada1' } }); // nosemgrep: ford.segredo-fixo-no-codigo
    return `Exclusão de conta com senha errada → ${r.status} ${r.erro || ''}`;
  },
  // IoT: uma leitura legítima, um odômetro voltando (módulo comprometido) e uma assinatura falsa
  async iot() {
    const d = DISPOSITIVOS[0];
    const v = VEICULOS_DB.find(x => x.id === d.veiculoId);
    const chave = await chaveDispositivo(d.id);
    const kmAtual = ultimaLeitura.has(d.id) ? ultimaLeitura.get(d.id).km : v.km;
    const agora = () => new Date().toISOString();
    const enviar = async (km, chaveUsada) => {
      const m = { device_id: d.id, vin: v.vin, km, ts: agora() };
      m.assinatura = await assinarTelemetria(m, chaveUsada);
      return receberTelemetria(m);
    };
    const r1 = await enviar(kmAtual + 2, chave);
    const r2 = await enviar(kmAtual - 1500, chave);
    const chaveFalsa = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const r3 = await enviar(kmAtual + 4, chaveFalsa);
    await atualizarInicioSeAberto();
    const txt = r => (r.aceita ? 'aceita' : `rejeitada (${r.motivo})`);
    return `Leitura normal: ${txt(r1)}. Odômetro voltando 1.500 km: ${txt(r2)}. Assinatura falsa: ${txt(r3)}.`;
  },
  // ML: muitas leituras seguidas dos leads, abaixo do rate limit
  async massa() {
    let ok = 0;
    for (let i = 0; i < 12; i++) {
      const r = await api('GET', '/v1/analytics/leads', sessao.token);
      if (r.status === 200) ok += 1;
    }
    return `12 consultas seguidas a /v1/analytics/leads: ${ok} respondidas. O rate limit não barrou (cada requisição é válida), mas o volume disparou o alerta de extração em massa.`;
  }
};

// Monta um pedido válido com o primeiro horário livre (usado pelas simulações)
function corpoValidoPara(veiculoId) {
  for (const data of diasDisponiveis())
    for (const c of CONCESSIONARIAS)
      for (const hora of HORARIOS)
        if (horarioLivre(c.id, data, hora))
          return { veiculo_id: veiculoId, servico: 'revisao', concessionaria_id: c.id, data, hora, observacoes: '' };
  return null;
}

async function atualizarInicioSeAberto() {
  if (tela.querySelector('.veiculo')) await telaCliente();
}

/* =========================================================
   18. RBAC CENTRAL, BASE ANALÍTICA E API DE GESTÃO
   ========================================================= */
// Matriz de permissões: cada rota exige uma permissão, e cada perfil só tem o mínimo necessário
const PERMISSOES = {
  cliente:  ['veiculos:ler_proprios', 'agendamentos:gerenciar_proprios', 'privacidade:gerenciar_proprios'],
  analista: ['vinshare:ler', 'leads:ler', 'leads:encaminhar'],
  admin:    ['usuarios:ler', 'usuarios:alterar_perfil', 'usuarios:encerrar_sessoes', 'usuarios:desbloquear', 'auditoria:ler']
};

function autorizar(payload, permissao, rota) {
  const suspensas = SUSPENSOES.get(payload.sub); // seção 25: suspensão aplicada na contenção de um incidente
  if (suspensas && suspensas.has(permissao)) {
    Log.registrar('access.denied_suspended', 'WARN', { user_id: payload.sub, route: rota, permission: permissao, reason: 'suspended_by_incident_response', status: 403 });
    return { status: 403, erro: 'Acesso suspenso pela equipe de segurança.' };
  }
  if ((PERMISSOES[payload.role] || []).includes(permissao)) return null;
  Log.registrar('access.denied', 'WARN', { user_id: payload.sub, role: payload.role, route: rota, required_permission: permissao, reason: 'perfil_sem_permissao', status: 403 });
  return { status: 403, erro: 'Você não tem permissão para esta ação.' };
}

// --- Frota sintética para o painel (gerador determinístico: sempre os mesmos números)
function prng(seed) {
  return () => {
    seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function mesesEntre(iso, ate = new Date()) {
  const d = dataLocal(iso);
  return (ate.getFullYear() - d.getFullYear()) * 12 + (ate.getMonth() - d.getMonth()) - (ate.getDate() < d.getDate() ? 1 : 0);
}
const MODELOS_FROTA = ['Ranger', 'Territory', 'Maverick', 'Bronco Sport', 'Transit'];

function montarFrota() {
  const r = prng(2026);
  const anoAtual = new Date().getFullYear();
  const frota = [];
  for (let i = 0; i < 64; i++) {
    const idade = 1 + Math.floor(r() * 7); // só veículos com 1 ano ou mais entram no VIN Share
    const mesesDesdeEntrega = idade * 12 + 1 + Math.floor(r() * 11);
    const conc = CONCESSIONARIAS[Math.floor(r() * CONCESSIONARIAS.length)].id;
    const chance = 0.92 - idade * 0.09 - (conc === 'c-103' ? 0.14 : 0); // retenção cai com a idade
    const naRede = r() < chance;
    const nunca = !naRede && r() < 0.3;
    const meses = naRede ? 1 + Math.floor(r() * 12)
      : nunca ? mesesDesdeEntrega
      : 13 + Math.floor(r() * (mesesDesdeEntrega - 12)); // nunca passa do tempo desde a entrega
    frota.push({
      id: 'f-' + (1001 + i), ownerId: 'u-' + (3001 + i),
      modelo: MODELOS_FROTA[Math.floor(r() * MODELOS_FROTA.length)], ano: anoAtual - idade, idade,
      concessionariaId: conc, mesesSemServico: meses, garantiaAtiva: idade < 3,
      km: Math.round((idade * 15000 * (0.6 + r() * 0.8)) / 100) * 100,
      nuncaNaRede: nunca
    });
  }
  // Os veículos reais do protótipo entram no mesmo cálculo
  VEICULOS_DB.forEach(v => {
    const concHist = v.historico[0] ? CONCESSIONARIAS.find(c => v.historico[0].local.startsWith(c.nome)) : null;
    frota.push({
      id: v.id, ownerId: v.ownerId, modelo: v.modelo, ano: v.ano,
      idade: Math.max(1, Math.floor(mesesEntre(v.entrega) / 12)),
      concessionariaId: concHist ? concHist.id : 'c-102',
      mesesSemServico: mesesEntre(v.ultimaRevisao ? v.ultimaRevisao.data : v.entrega),
      garantiaAtiva: dataLocal(v.garantiaFim) > new Date(), km: v.km, nuncaNaRede: !v.ultimaRevisao
    });
  });
  return frota;
}
const FROTA = montarFrota();

// --- Pseudoanonimização: o analista vê "CLI-XXXXXXXX" em vez do cliente.
// A tabela que liga pseudônimo -> cliente fica só no servidor e nunca sai pela API.
let chavePseudonimo = null;
const TABELA_PSEUDONIMOS = new Map();
async function pseudonimo(ownerId) {
  if (!chavePseudonimo) chavePseudonimo = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const assinatura = await crypto.subtle.sign('HMAC', chavePseudonimo, enc.encode(ownerId));
  const ref = 'CLI-' + bytesParaHex(assinatura).slice(0, 8).toUpperCase();
  TABELA_PSEUDONIMOS.set(ref, ownerId);
  return ref;
}

// --- VIN Share: % de veículos com serviço na rede nos últimos 12 meses
function calcularVinShare() {
  const naRede = v => v.mesesSemServico <= 12;
  const agrupar = (chaveFn, rotuloFn, ordenar) => {
    const g = new Map();
    FROTA.forEach(v => {
      const k = chaveFn(v);
      const x = g.get(k) || { chave: k, rotulo: rotuloFn(k), total: 0, naRede: 0 };
      x.total += 1;
      if (naRede(v)) x.naRede += 1;
      g.set(k, x);
    });
    return [...g.values()].map(x => ({ ...x, pct: x.naRede / x.total })).sort(ordenar || ((a, b) => b.pct - a.pct));
  };
  const faixaIdade = i => (i <= 2 ? '1 a 2 anos' : i <= 4 ? '3 a 4 anos' : '5 anos ou mais');
  const total = FROTA.length;
  const dentro = FROTA.filter(naRede).length;
  return {
    geral: { total, naRede: dentro, pct: dentro / total },
    porConcessionaria: agrupar(v => v.concessionariaId, id => CONCESSIONARIAS.find(c => c.id === id).nome),
    porIdade: agrupar(v => faixaIdade(v.idade), k => k, (a, b) => a.chave.localeCompare(b.chave)),
    porModelo: agrupar(v => v.modelo, k => k)
  };
}

// --- Leads: veículos com 10+ meses sem serviço na rede
const STATUS_LEADS = new Map(); // leadId -> { status, em, por }
const faixaKm = km => (km < 20000 ? 'até 20 mil km' : km < 50000 ? '20 a 50 mil km' : km < 100000 ? '50 a 100 mil km' : 'mais de 100 mil km');

async function gerarLeads() {
  const leads = [];
  for (const v of FROTA) {
    if (v.mesesSemServico < 10) continue;
    const alta = v.mesesSemServico > 12; // já saiu da janela de 12 meses do VIN Share
    const partes = [`Sem serviço na rede há ${v.mesesSemServico} meses.`];
    if (v.nuncaNaRede) partes.push('Nunca voltou à rede depois da compra.');
    if (!v.garantiaAtiva) partes.push('Garantia de fábrica encerrada.');
    const id = 'L-' + v.id.replace(/\D/g, '');
    const conc = CONCESSIONARIAS.find(c => c.id === v.concessionariaId);
    const salvo = STATUS_LEADS.get(id);
    leads.push({
      id, cliente_ref: await pseudonimo(v.ownerId), modelo: v.modelo, ano: v.ano,
      km_faixa: faixaKm(v.km), meses_sem_servico: v.mesesSemServico, garantia_ativa: v.garantiaAtiva,
      concessionaria_id: conc.id, concessionaria: conc.nome,
      prioridade: alta ? 'alta' : 'media', motivo: partes.join(' '),
      status: agendamentoAtivo(v.id) ? 'agendado'
        : !consentimentosDe(v.ownerId).contato_concessionaria ? 'sem_consentimento' // LGPD: sem autorização, sem contato
        : salvo ? salvo.status : 'novo'
    });
  }
  return leads.sort((a, b) => (a.prioridade === b.prioridade ? b.meses_sem_servico - a.meses_sem_servico : a.prioridade === 'alta' ? -1 : 1));
}

// --- Usuários (visão do admin)
function usuarioDTO(u) {
  return {
    id: u.id, nome: u.nome, email: u.email, perfil: u.perfil,
    bloqueado: estadoBloqueio(u.email) > 0, pode_entrar: Boolean(u.hash), ultimo_login: u.ultimoLogin,
    excluida: Boolean(u.excluido)
  };
}

function alterarPerfil(payload, id, corpo) {
  const rota = '/v1/admin/users/{id}';
  const negado = autorizar(payload, 'usuarios:alterar_perfil', rota);
  if (negado) return negado;
  const u = /^u-\d{4}$/.test(id) ? USUARIOS.find(x => x.id === id) : null;
  if (!u) return { status: 404, erro: 'Usuário não encontrado.' };
  if (!corpo || typeof corpo !== 'object' || Object.keys(corpo).some(k => k !== 'perfil') || !Object.hasOwn(PERFIS, corpo.perfil)) {
    Log.registrar('api.input.rejected', 'WARN', { user_id: payload.sub, route: rota, reason: 'invalid_body', status: 400 });
    return { status: 400, erro: 'Perfil inválido.' };
  }
  if (u.id === payload.sub) {
    Log.registrar('admin.user.self_change_blocked', 'WARN', { user_id: payload.sub, audit: true, status: 409 });
    return { status: 409, erro: 'Você não pode alterar o próprio perfil.' };
  }
  if (u.perfil === corpo.perfil) return { status: 200, dados: usuarioDTO(u) };
  const antes = u.perfil;
  u.perfil = corpo.perfil;
  u.versaoToken += 1; // derruba os tokens que ainda carregam o perfil antigo
  Log.registrar('admin.user.role_changed', 'WARN', { user_id: payload.sub, target_user: u.id, from: antes, to: u.perfil, sessions_revoked: true, audit: true, status: 200 });
  return { status: 200, dados: usuarioDTO(u) };
}

function acaoConta(payload, id, acao) {
  const permissao = acao === 'unlock' ? 'usuarios:desbloquear' : 'usuarios:encerrar_sessoes';
  const rota = `/v1/admin/users/{id}/${acao}`;
  const negado = autorizar(payload, permissao, rota);
  if (negado) return negado;
  const u = /^u-\d{4}$/.test(id) ? USUARIOS.find(x => x.id === id) : null;
  if (!u) return { status: 404, erro: 'Usuário não encontrado.' };
  if (acao === 'revoke-sessions') {
    if (u.id === payload.sub) return { status: 409, erro: 'Use o botão Sair para encerrar a sua própria sessão.' };
    u.versaoToken += 1;
    Log.registrar('admin.user.sessions_revoked', 'WARN', { user_id: payload.sub, target_user: u.id, audit: true, status: 200 });
  } else {
    if (!estadoBloqueio(u.email)) return { status: 409, erro: 'Esta conta não está bloqueada.' };
    tentativas.delete(u.email);
    Log.registrar('admin.user.unlocked', 'WARN', { user_id: payload.sub, target_user: u.id, audit: true, status: 200 });
  }
  return { status: 200, dados: usuarioDTO(u) };
}

// Eventos que entram na trilha de auditoria
const EVENTOS_AUDITORIA = /^(auth\.account\.lockout|auth\.login\.(success|failure)|access\.denied|api\.authz\.|api\.auth\.rejected|admin\.|lead\.|appointment\.(created|cancelled)|data\.sensitive\.read|data\.location\.used|privacy\.|storage\.cache\.integrity_fail|alert\.|iot\.telemetry\.rejected|ir\.(action|incident)|waf\.)/;

async function rotasGestao(metodo, rota, payload, opcoes) {
  let m;

  if (metodo === 'GET' && rota === '/v1/analytics/vin-share') {
    const negado = autorizar(payload, 'vinshare:ler', rota);
    if (negado) return negado;
    Log.registrar('data.access', 'INFO', { user_id: payload.sub, route: rota, status: 200, records: FROTA.length, aggregated: true });
    return { status: 200, dados: calcularVinShare() };
  }

  if (metodo === 'GET' && rota === '/v1/analytics/leads') {
    const negado = autorizar(payload, 'leads:ler', rota);
    if (negado) return negado;
    const leads = await gerarLeads();
    Log.registrar('data.access', 'INFO', { user_id: payload.sub, route: rota, status: 200, records: leads.length, pseudonymized: true });
    return { status: 200, dados: leads };
  }

  if (metodo === 'POST' && (m = rota.match(/^\/v1\/leads\/([^/]+)\/forward$/))) {
    const rotaModelo = '/v1/leads/{id}/forward';
    const negado = autorizar(payload, 'leads:encaminhar', rotaModelo);
    if (negado) return negado;
    if (!/^L-\d{4}$/.test(m[1])) {
      Log.registrar('api.input.rejected', 'WARN', { user_id: payload.sub, route: rotaModelo, reason: 'invalid_id_format', status: 400 });
      return { status: 400, erro: 'Identificador inválido.' };
    }
    const lead = (await gerarLeads()).find(l => l.id === m[1]);
    if (!lead) return { status: 404, erro: 'Lead não encontrado.' };
    if (lead.status === 'sem_consentimento') {
      Log.registrar('lead.forward_blocked', 'WARN', { user_id: payload.sub, lead_id: lead.id, reason: 'no_contact_consent', audit: true, status: 409 });
      return { status: 409, erro: 'O cliente não autorizou contato da concessionária.' };
    }
    if (lead.status !== 'novo') return { status: 409, erro: 'Este lead já foi tratado.' };
    STATUS_LEADS.set(lead.id, { status: 'encaminhado', em: new Date().toISOString(), por: payload.sub });
    Log.registrar('lead.forwarded', 'INFO', { user_id: payload.sub, lead_id: lead.id, dealer_id: lead.concessionaria_id, audit: true, status: 200 });
    return { status: 200, dados: { ...lead, status: 'encaminhado' } };
  }

  if (metodo === 'GET' && rota === '/v1/admin/users') {
    const negado = autorizar(payload, 'usuarios:ler', rota);
    if (negado) return negado;
    return { status: 200, dados: USUARIOS.map(usuarioDTO) };
  }

  if (metodo === 'PATCH' && (m = rota.match(/^\/v1\/admin\/users\/([^/]+)$/))) return alterarPerfil(payload, m[1], opcoes.corpo);

  if (metodo === 'POST' && (m = rota.match(/^\/v1\/admin\/users\/([^/]+)\/(revoke-sessions|unlock)$/))) return acaoConta(payload, m[1], m[2]);

  if (metodo === 'GET' && rota === '/v1/admin/audit') {
    const negado = autorizar(payload, 'auditoria:ler', rota);
    if (negado) return negado;
    const itens = Log.itens.filter(e => EVENTOS_AUDITORIA.test(e.event)).slice(-60).reverse().map(e => ({
      timestamp: e.timestamp, level: e.level, event: e.event,
      ator: e.user_id || e.user || 'anônimo',
      alvo: e.target_user || e.target_resource || e.lead_id || e.appointment_id || '',
      detalhe: e.reason || (e.from ? `${e.from} para ${e.to}` : '') || e.route || e.outcome || ''
    }));
    Log.registrar('admin.audit.viewed', 'INFO', { user_id: payload.sub, audit: true, records: itens.length }); // quem olhou a auditoria também fica registrado
    return { status: 200, dados: itens };
  }

  return null;
}

/* =========================================================
   19. TELAS DO ANALISTA FORD (VIN Share e leads)
   ========================================================= */
const pct = x => Math.round(x * 100) + '%';

function montarTopoPerfil(payload) {
  const usuario = USUARIOS.find(u => u.id === payload.sub);
  tela.innerHTML = `
    <div class="topbar">
      <div class="topline">
        <p class="brand">Ford Pós-Venda</p>
        <button class="btn-sair" id="btnSair" type="button">Sair</button>
      </div>
      <h1 id="saudacao"></h1>
      <p class="sessao-linha"><span id="rotPerfil"></span>, sessão expira em <span class="countdown" id="kvExpira"></span></p>
    </div>
    <div class="body" id="corpo"></div>`;
  document.getElementById('saudacao').textContent = `Olá, ${usuario.nome.split(' ')[0]}`;
  document.getElementById('rotPerfil').textContent = PERFIS[payload.role].rotulo;
  document.getElementById('btnSair').addEventListener('click', () => encerrarSessao('logout'));
  iniciarTimerSessao(payload);
  return document.getElementById('corpo');
}

function barraAbas(corpo, abas, ativa, aoTrocar) {
  corpo.append(el('div', { class: 'abas', role: 'tablist' },
    abas.map(([id, rotulo]) => el('button', {
      type: 'button', class: 'aba', role: 'tab', 'aria-selected': String(id === ativa),
      onclick: () => { if (id !== ativa) aoTrocar(id); }
    }, rotulo))));
}

async function telaAnalista(aba = 'painel') {
  const payload = await exigirSessao(['analista']);
  if (!payload) return encerrarSessao('expirou');
  const corpo = montarTopoPerfil(payload);
  barraAbas(corpo, [['painel', 'VIN Share'], ['leads', 'Leads']], aba, a => telaAnalista(a));
  if (aba === 'painel') return desenharPainelVinShare(corpo);
  return desenharLeads(corpo);
}

function cardBarras(titulo, itens, insight) {
  return el('section', { class: 'card' },
    el('h2', {}, titulo),
    el('ul', { class: 'barras' }, itens.map(i => {
      const nivel = i.pct < 0.5 ? 'atrasada' : i.pct < 0.7 ? 'proxima' : '';
      return el('li', {},
        el('span', {}, i.rotulo),
        el('span', { class: 'val' }, pct(i.pct) + ' ', el('small', {}, `(${i.naRede} de ${i.total})`)),
        el('div', { class: 'barra ' + nivel }, el('span', { style: `width:${Math.round(i.pct * 100)}%` })));
    })),
    insight ? el('p', { class: 'insight' }, insight) : null);
}

async function desenharPainelVinShare(corpo) {
  const r = await api('GET', '/v1/analytics/vin-share', sessao.token);
  if (r.status === 401) return encerrarSessao('expirou');
  if (r.status !== 200) return corpo.append(el('div', { class: 'alert alert-error' }, r.erro));
  const d = r.dados;
  const pior = d.porConcessionaria[d.porConcessionaria.length - 1];
  corpo.append(
    el('section', { class: 'confirmado', 'aria-label': 'VIN Share geral' },
      el('p', { class: 'rot' }, 'VIN Share nos últimos 12 meses'),
      el('p', { class: 'kpi' }, pct(d.geral.pct)),
      el('p', { class: 'rot' }, `${d.geral.naRede} de ${d.geral.total} veículos fizeram serviço na rede Ford.`)),
    cardBarras('Por concessionária', d.porConcessionaria, `${pior.rotulo} tem o menor índice. Os clientes em risco dessa região estão na aba Leads.`),
    cardBarras('Por idade do veículo', d.porIdade, 'Nesta base, a retenção cai conforme o veículo envelhece e sai da garantia.'),
    cardBarras('Por modelo', d.porModelo),
    el('p', { class: 'muted' }, 'Base: veículos entregues há 12 meses ou mais. O painel recebe só números agregados, sem nome, placa ou VIN.'));
}

let filtroLeads = 'todos';

async function desenharLeads(corpo) {
  const r = await api('GET', '/v1/analytics/leads', sessao.token);
  if (r.status === 401) return encerrarSessao('expirou');
  if (r.status !== 200) return corpo.append(el('div', { class: 'alert alert-error' }, r.erro));
  const leads = r.dados;
  const contar = f => leads.filter(f).length;
  corpo.append(el('p', { class: 'muted' },
    `${leads.length} veículos com risco de sair da rede, ${contar(l => l.prioridade === 'alta')} com prioridade alta. ` +
    `${contar(l => l.status === 'agendado')} já agendaram e ${contar(l => l.status === 'encaminhado')} foram encaminhados.`));

  const filtros = el('div', { class: 'chips', role: 'group', 'aria-label': 'Filtrar por prioridade' });
  const lista = el('div', { class: 'lista-leads' });
  const desenhar = () => {
    filtros.innerHTML = '';
    [['todos', 'Todos'], ['alta', 'Alta'], ['media', 'Média']].forEach(([id, rotulo]) =>
      filtros.append(el('button', { type: 'button', class: 'chip', 'aria-pressed': String(filtroLeads === id),
        onclick: () => { filtroLeads = id; desenhar(); } }, rotulo)));
    lista.innerHTML = '';
    leads.filter(l => filtroLeads === 'todos' || l.prioridade === filtroLeads).forEach(l => lista.append(cardLead(l)));
  };
  corpo.append(filtros, lista,
    el('p', { class: 'muted' }, 'Os clientes aparecem por código (pseudônimo). Nome e contato ficam com a concessionária, que recebe o lead encaminhado.'));
  desenhar();
}

function cardLead(l) {
  const acao = el('div', { class: 'lead-acao' });
  const desenharAcao = () => {
    acao.innerHTML = '';
    if (l.status === 'novo') {
      const b = el('button', { type: 'button', class: 'btn-sm' }, 'Encaminhar à concessionária');
      const erro = el('span', { class: 'nota', style: 'margin:0' });
      b.addEventListener('click', async () => {
        b.disabled = true;
        const r = await api('POST', `/v1/leads/${l.id}/forward`, sessao.token);
        if (r.status === 401) return encerrarSessao('expirou');
        if (r.status === 200) { l.status = 'encaminhado'; return desenharAcao(); }
        b.disabled = false;
        erro.textContent = r.erro;
      });
      acao.append(erro, b);
    } else if (l.status === 'sem_consentimento') {
      acao.append(el('span', { class: 'pill revogado' }, 'Sem autorização'), el('span', { class: 'nota', style: 'margin:0' }, 'Cliente não aceita contato'));
    } else if (l.status === 'agendado') {
      acao.append(el('span', { class: 'pill agendado' }, 'Agendou revisão'), el('span', { class: 'nota', style: 'margin:0' }, 'Pelo app do cliente'));
    } else {
      acao.append(el('span', { class: 'pill encaminhado' }, 'Encaminhado'), el('span', { class: 'nota', style: 'margin:0' }, `Para ${l.concessionaria}`));
    }
  };
  desenharAcao();
  return el('article', { class: 'card lead' },
    el('div', { class: 'card-head' },
      el('span', { class: 'lead-ref' }, l.cliente_ref),
      el('span', { class: 'pill ' + l.prioridade }, l.prioridade === 'alta' ? 'Alta' : 'Média')),
    el('p', {}, el('strong', {}, `${l.modelo} ${l.ano}`), `, ${l.km_faixa}`),
    el('p', { class: 'motivo' }, l.motivo),
    el('p', { class: 'motivo' }, `Concessionária de referência: ${l.concessionaria}`),
    acao);
}

/* =========================================================
   20. TELAS DO ADMINISTRADOR (usuários, auditoria, permissões)
   ========================================================= */
async function telaAdmin(aba = 'usuarios') {
  const payload = await exigirSessao(['admin']);
  if (!payload) return encerrarSessao('expirou');
  const corpo = montarTopoPerfil(payload);
  barraAbas(corpo, [['usuarios', 'Usuários'], ['auditoria', 'Auditoria'], ['permissoes', 'Permissões']], aba, a => telaAdmin(a));
  if (aba === 'usuarios') return desenharUsuarios(corpo, payload);
  if (aba === 'auditoria') return desenharAuditoria(corpo);
  desenharPermissoes(corpo);
}

async function desenharUsuarios(corpo, payload) {
  const r = await api('GET', '/v1/admin/users', sessao.token);
  if (r.status === 401) return encerrarSessao('expirou');
  if (r.status !== 200) return corpo.append(el('div', { class: 'alert alert-error' }, r.erro));
  r.dados.forEach(u => corpo.append(cardUsuario(u, payload)));
}

function cardUsuario(u, payload) {
  const msg = el('p', { class: 'nota', role: 'status' });
  const estado = u.excluida ? 'Conta excluída a pedido do titular'
    : u.bloqueado ? 'Bloqueada por excesso de tentativas' : u.pode_entrar ? 'Ativa' : 'Ativa, sem senha de demonstração';
  const ultimo = u.ultimo_login ? `Último acesso às ${new Date(u.ultimo_login).toLocaleTimeString('pt-BR')}` : 'Sem acesso nesta sessão do protótipo';
  const card = el('article', { class: 'card usuario' },
    el('div', { class: 'card-head' }, el('h2', {}, u.nome), el('span', { class: 'pill perfil' }, PERFIS[u.perfil].rotulo)),
    el('p', { class: 'motivo' }, u.email),
    el('p', { class: 'motivo' + (u.bloqueado ? ' alerta' : '') }, `${estado}. ${ultimo}.`));

  if (u.id === payload.sub) {
    card.append(el('p', { class: 'nota' }, 'Esta é a sua conta. O seu perfil só pode ser alterado por outro administrador.'));
    return card;
  }
  if (u.excluida) return card; // nada a gerenciar: os dados pessoais já foram removidos

  // Alterar perfil (confirmação em dois toques)
  const sel = el('select', { 'aria-label': `Perfil de ${u.nome}` },
    Object.entries(PERFIS).map(([id, p]) => {
      const o = el('option', { value: id }, p.rotulo);
      o.selected = id === u.perfil;
      return o;
    }));
  const salvar = el('button', { type: 'button', class: 'btn-sm' }, 'Salvar perfil');
  let armado = false;
  let t = null;
  salvar.addEventListener('click', async () => {
    if (sel.value === u.perfil) { msg.textContent = 'Escolha um perfil diferente do atual.'; return; }
    if (!armado) {
      armado = true;
      salvar.textContent = 'Confirmar';
      msg.textContent = `A mudança encerra as sessões abertas de ${u.nome.split(' ')[0]}.`;
      t = setTimeout(() => { armado = false; salvar.textContent = 'Salvar perfil'; msg.textContent = ''; }, 5000);
      return;
    }
    clearTimeout(t);
    salvar.disabled = true;
    const r = await api('PATCH', `/v1/admin/users/${u.id}`, sessao.token, { corpo: { perfil: sel.value } });
    if (r.status === 401) return encerrarSessao('expirou');
    if (r.status === 200) return telaAdmin('usuarios');
    salvar.disabled = false;
    armado = false;
    salvar.textContent = 'Salvar perfil';
    msg.textContent = r.erro;
  });

  const encerrar = el('button', { type: 'button', class: 'btn-sm ghost' }, 'Encerrar sessões');
  encerrar.addEventListener('click', async () => {
    encerrar.disabled = true;
    const r = await api('POST', `/v1/admin/users/${u.id}/revoke-sessions`, sessao.token);
    if (r.status === 401) return encerrarSessao('expirou');
    encerrar.disabled = false;
    msg.textContent = r.status === 200 ? 'Sessões encerradas. O próximo acesso exige novo login.' : r.erro;
  });

  const acoes = el('div', { class: 'acoes' }, el('div', { class: 'linha-perfil' }, sel, salvar), encerrar);
  if (u.bloqueado) {
    const desbloquear = el('button', { type: 'button', class: 'btn-sm ghost' }, 'Desbloquear conta');
    desbloquear.addEventListener('click', async () => {
      desbloquear.disabled = true;
      const r = await api('POST', `/v1/admin/users/${u.id}/unlock`, sessao.token);
      if (r.status === 401) return encerrarSessao('expirou');
      if (r.status === 200) return telaAdmin('usuarios');
      desbloquear.disabled = false;
      msg.textContent = r.erro;
    });
    acoes.append(desbloquear);
  }
  card.append(acoes, msg);
  return card;
}

async function desenharAuditoria(corpo) {
  const r = await api('GET', '/v1/admin/audit', sessao.token);
  if (r.status === 401) return encerrarSessao('expirou');
  if (r.status !== 200) return corpo.append(el('div', { class: 'alert alert-error' }, r.erro));
  corpo.append(
    el('div', { class: 'card-head' },
      el('p', { class: 'muted' }, `${plural(r.dados.length, 'evento de segurança', 'eventos de segurança')}, do mais recente ao mais antigo.`),
      el('button', { type: 'button', class: 'btn-sm ghost', onclick: () => telaAdmin('auditoria') }, 'Atualizar')),
    el('section', { class: 'card' },
      r.dados.length
        ? el('ol', { class: 'audit' }, r.dados.map(e => el('li', {},
            el('time', { datetime: e.timestamp }, new Date(e.timestamp).toLocaleTimeString('pt-BR')),
            el('span', { class: 'ev ' + e.level }, e.event),
            el('span', { class: 'det' }, [e.ator, e.alvo && `alvo ${e.alvo}`, e.detalhe].filter(Boolean).join(', ')))))
        : el('p', { class: 'muted' }, 'Nenhum evento registrado ainda.')));
}

function desenharPermissoes(corpo) {
  const todas = [...new Set(Object.values(PERMISSOES).flat())];
  const perfis = Object.keys(PERFIS);
  corpo.append(
    el('p', { class: 'muted' }, 'Cada rota da API exige uma permissão, e cada perfil só tem o mínimo que precisa. O Administrador não vê leads, e o Analista não gerencia usuários.'),
    el('section', { class: 'card' },
      el('div', { class: 'tabela-wrap' },
        el('table', { class: 'matriz' },
          el('thead', {}, el('tr', {}, el('th', { scope: 'col' }, 'Permissão'), perfis.map(p => el('th', { scope: 'col' }, { cliente: 'Cliente', analista: 'Analista', admin: 'Admin' }[p])))),
          el('tbody', {}, todas.map(perm => el('tr', {},
            el('th', { scope: 'row' }, perm.split(/(?<=[:_])/).flatMap((parte, i) => (i ? [el('wbr'), parte] : [parte]))),
            perfis.map(p => (PERMISSOES[p].includes(perm)
              ? el('td', { class: 'sim', 'aria-label': 'permitido' }, '✓')
              : el('td', { class: 'nao', 'aria-label': 'negado' }, '–'))))))))));
}

/* =========================================================
   21. PRIVACIDADE E LGPD: consentimentos, localização, portabilidade e exclusão
   ========================================================= */
const POLITICA_VERSAO = '2026.1';
const CONTATO_DPO = 'privacidade@ford-posvenda.example';

// Finalidades de tratamento que dependem de consentimento (LGPD art. 7º, I)
const FINALIDADES = {
  telemetria:             { titulo: 'Telemetria do veículo',     desc: 'Quilometragem e alertas enviados pelo veículo conectado, usados para calcular a próxima revisão.' },
  localizacao:            { titulo: 'Localização do veículo',    desc: 'Usada só para sugerir a concessionária mais próxima quando você agenda.' },
  lembretes:              { titulo: 'Lembretes de revisão',      desc: 'Avisos por e-mail e notificação quando a revisão estiver chegando.' },
  ofertas:                { titulo: 'Ofertas e promoções',       desc: 'Campanhas de peças, acessórios e serviços da rede Ford.' },
  contato_concessionaria: { titulo: 'Contato da concessionária', desc: 'Permite que a concessionária de referência fale com você quando o veículo estiver sem revisão.' }
};
const CONSENTIMENTO_PADRAO = { telemetria: true, localizacao: false, lembretes: true, ofertas: false, contato_concessionaria: true };

const CONSENTIMENTOS = new Map();       // userId -> { finalidade: true/false }
const HISTORICO_CONSENTIMENTO = [];     // prova de cada aceite e retirada (quem, o quê, quando, versão da política)

function consentimentosDe(userId) {
  if (!CONSENTIMENTOS.has(userId)) CONSENTIMENTOS.set(userId, { ...CONSENTIMENTO_PADRAO });
  return CONSENTIMENTOS.get(userId);
}

// Aceites iniciais da Mariana, feitos no cadastro com a política da época
['telemetria', 'lembretes', 'contato_concessionaria'].forEach(f =>
  HISTORICO_CONSENTIMENTO.push({ userId: 'u-1001', finalidade: f, concedido: true, versao: '2024.1', em: '2024-02-10T13:00:00.000Z', canal: 'cadastro' }));

// Política de retenção do projeto
const RETENCAO = [
  ['Telemetria do veículo', '12 meses. Depois disso, só em números agregados, sem identificar você.'],
  ['Agendamentos e histórico de serviços', 'Enquanto o veículo estiver ligado à sua conta.'],
  ['Registros de acesso ao app', '6 meses, como exige o Marco Civil da Internet.'],
  ['Dados da conta', 'Até você pedir a exclusão.']
];

// Localização: fica só no servidor. O app recebe a distância, nunca a coordenada.
const COORD_CONCESSIONARIAS = {
  'c-101': { lat: -23.5025, lng: -46.6252 },
  'c-102': { lat: -23.5612, lng: -46.6453 },
  'c-103': { lat: -23.6541, lng: -46.7085 }
};
const LOCALIZACAO_VEICULOS = {
  'v-5001': { lat: -23.5891, lng: -46.6342 },
  'v-5002': { lat: -23.6203, lng: -46.6901 },
  'v-5099': { lat: -23.5405, lng: -46.6380 }
};

function distanciaKm(a, b) {
  const rad = x => (x * Math.PI) / 180;
  const dLat = rad(b.lat - a.lat);
  const dLng = rad(b.lng - a.lng);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLng / 2) ** 2;
  return 2 * 6371 * Math.asin(Math.sqrt(h));
}

function listarConcessionarias(payload, veiculoId) {
  const base = CONCESSIONARIAS.map(c => ({ ...c }));
  if (!veiculoId) return { status: 200, dados: base, localizacao_usada: false };
  if (!/^v-\d{4}$/.test(veiculoId)) {
    Log.registrar('api.input.rejected', 'WARN', { user_id: payload.sub, route: '/v1/dealers', reason: 'invalid_vehicle_param', status: 400 });
    return { status: 400, erro: 'Parâmetros inválidos.' };
  }
  const v = VEICULOS_DB.find(x => x.id === veiculoId);
  if (!v || v.ownerId !== payload.sub) {
    if (v) Log.registrar('api.authz.bola_attempt', 'CRITICAL', { user_id: payload.sub, route: '/v1/dealers?veiculo_id', target_resource: v.id, status: 404, reason: 'resource_owned_by_another_user' });
    return { status: 404, erro: 'Veículo não encontrado.' };
  }
  // Sem consentimento de localização: devolve a lista sem usar a posição do veículo
  if (!consentimentosDe(payload.sub).localizacao) return { status: 200, dados: base, localizacao_usada: false };
  const loc = LOCALIZACAO_VEICULOS[v.id];
  const dados = base
    .map(c => ({ ...c, distancia_km: Math.round(distanciaKm(loc, COORD_CONCESSIONARIAS[c.id]) * 10) / 10 }))
    .sort((a, b) => a.distancia_km - b.distancia_km);
  Log.registrar('data.location.used', 'INFO', { user_id: payload.sub, vehicle_id: v.id, purpose: 'sugerir_concessionaria', consent: true });
  return { status: 200, dados, localizacao_usada: true };
}

function consentimentosDTO(userId) {
  return {
    politica_versao: POLITICA_VERSAO,
    atual: { ...consentimentosDe(userId) },
    historico: HISTORICO_CONSENTIMENTO.filter(h => h.userId === userId).slice().reverse().slice(0, 20)
      .map(h => ({ finalidade: h.finalidade, concedido: h.concedido, versao: h.versao, em: h.em, canal: h.canal }))
  };
}

// Portabilidade: tudo o que é do titular, em formato estruturado. Sem dados de segurança.
function montarExportacao(u) {
  const cons = consentimentosDe(u.id);
  return {
    gerado_em: new Date().toISOString(),
    formato: 'JSON estruturado',
    titular: { id: u.id, nome: u.nome, email: u.email, perfil: u.perfil, ultimo_login: u.ultimoLogin },
    veiculos: VEICULOS_DB.filter(v => v.ownerId === u.id).map(v => ({
      id: v.id, modelo: v.modelo, versao: v.versao, ano: v.ano, placa: v.placa, vin: v.vin, km: v.km,
      entrega: v.entrega, garantia_fim: v.garantiaFim, historico_servicos: v.historico,
      ...(cons.telemetria ? { telemetria_ultima_leitura: v.telemetriaEm } : {}),
      ...(cons.localizacao && LOCALIZACAO_VEICULOS[v.id] ? { localizacao: LOCALIZACAO_VEICULOS[v.id] } : {})
    })),
    agendamentos: AGENDAMENTOS_DB.filter(a => a.ownerId === u.id).map(agendamentoDTO),
    consentimentos: consentimentosDTO(u.id),
    nao_incluido: 'Dados de segurança da conta (hash da senha, chaves e tokens) não são exportados.'
  };
}

// Exclusão: apaga o que identifica a pessoa e desfaz o vínculo com os veículos
function anonimizarConta(u) {
  const anon = 'anon-' + u.id.slice(2);
  AGENDAMENTOS_DB.filter(a => a.ownerId === u.id).forEach(a => {
    if (a.status === 'confirmado') { a.status = 'cancelado'; a.canceladoEm = new Date().toISOString(); }
    a.observacoes = '';
    a.ownerId = anon;
  });
  VEICULOS_DB.filter(v => v.ownerId === u.id).forEach(v => { v.ownerId = anon; });
  FROTA.filter(f => f.ownerId === u.id).forEach(f => { f.ownerId = anon; });
  CONSENTIMENTOS.set(anon, Object.fromEntries(Object.keys(FINALIDADES).map(k => [k, false])));
  CONSENTIMENTOS.delete(u.id);
  for (let i = HISTORICO_CONSENTIMENTO.length - 1; i >= 0; i--)
    if (HISTORICO_CONSENTIMENTO[i].userId === u.id) HISTORICO_CONSENTIMENTO.splice(i, 1);
  u.nome = 'Titular removido';
  u.email = `removido-${u.id}@anon.invalid`;
  delete u.hash;
  delete u.salt;
  u.versaoToken += 1; // derruba a sessão aberta
  u.excluido = true;
}

async function rotasPrivacidade(metodo, rota, payload, opcoes) {
  const ROTAS = ['/v1/me/consents', '/v1/me/data-export', '/v1/me/deletion'];
  if (!ROTAS.includes(rota)) return null;
  const negado = autorizar(payload, 'privacidade:gerenciar_proprios', rota);
  if (negado) return negado;
  const u = USUARIOS.find(x => x.id === payload.sub); // o titular vem SEMPRE do token, nunca de parâmetro

  if (metodo === 'GET' && rota === '/v1/me/consents') return { status: 200, dados: consentimentosDTO(u.id) };

  if (metodo === 'PUT' && rota === '/v1/me/consents') {
    const c = opcoes.corpo;
    const valido = c && typeof c === 'object' && !Array.isArray(c) && Object.keys(c).length > 0 &&
      Object.entries(c).every(([k, v]) => Object.hasOwn(FINALIDADES, k) && typeof v === 'boolean');
    if (!valido) {
      Log.registrar('api.input.rejected', 'WARN', { user_id: u.id, route: rota, reason: 'invalid_body', status: 400 });
      return { status: 400, erro: 'Pedido de consentimento inválido.' };
    }
    const atual = consentimentosDe(u.id);
    for (const [f, valor] of Object.entries(c)) {
      if (atual[f] === valor) continue;
      atual[f] = valor;
      HISTORICO_CONSENTIMENTO.push({ userId: u.id, finalidade: f, concedido: valor, versao: POLITICA_VERSAO, em: new Date().toISOString(), canal: 'app' });
      Log.registrar(valor ? 'privacy.consent.granted' : 'privacy.consent.revoked', 'INFO', { user_id: u.id, purpose: f, policy_version: POLITICA_VERSAO, audit: true });
    }
    return { status: 200, dados: consentimentosDTO(u.id) };
  }

  if (metodo === 'GET' && rota === '/v1/me/data-export') {
    if (opcoes.query && Object.keys(opcoes.query).length)
      Log.registrar('api.input.ignored_params', 'WARN', { user_id: u.id, route: rota, params: Object.keys(opcoes.query), reason: 'rota_me_usa_apenas_o_token' });
    Log.registrar('privacy.data_export', 'INFO', { user_id: u.id, audit: true, status: 200 });
    return { status: 200, dados: montarExportacao(u) };
  }

  if (metodo === 'POST' && rota === '/v1/me/deletion') {
    const c = opcoes.corpo;
    if (!c || typeof c !== 'object' || Object.keys(c).some(k => k !== 'senha') || typeof c.senha !== 'string' || !c.senha || c.senha.length > CONFIG.SENHA_MAX) {
      Log.registrar('api.input.rejected', 'WARN', { user_id: u.id, route: rota, reason: 'invalid_body', status: 400 });
      return { status: 400, erro: 'Informe sua senha para confirmar.' };
    }
    if (estadoBloqueio(u.email)) return { status: 429, erro: 'Muitas tentativas. Aguarde para tentar novamente.' };

    // Reautenticação: ação irreversível exige a senha de novo, não basta o token
    const confere = await autenticar(u.email, c.senha);
    if (!confere) {
      const r = registrarFalha(u.email);
      Log.registrar('privacy.deletion.reauth_failed', 'WARN', { user_id: u.id, attempts_left: r.restantes, audit: true, status: 403 });
      if (r.bloqueou) Log.registrar('auth.account.lockout', 'CRITICAL', { user: mascararEmail(u.email), account_ref: refConta(u.email), reason: 'brute_force_suspected', threshold: CONFIG.MAX_TENTATIVAS, lock_seconds: CONFIG.BLOQUEIO_MS / 1000 });
      return { status: 403, erro: r.bloqueou ? 'Senha incorreta. Conta bloqueada por 60 segundos.' : `Senha incorreta. Restam ${plural(r.restantes, 'tentativa', 'tentativas')}.` };
    }
    tentativas.delete(u.email);
    anonimizarConta(u);
    Log.registrar('privacy.account_deleted', 'WARN', {
      user_id: u.id, audit: true, status: 200,
      data_removed: ['nome', 'email', 'senha', 'vinculo_veiculos', 'observacoes', 'consentimentos']
    });
    return { status: 200, dados: { excluida: true } };
  }
  return null;
}

/* =========================================================
   22. TELAS DE PRIVACIDADE (consentimentos, meus dados, excluir conta)
   ========================================================= */
function cardPrivacidade() {
  return el('section', { class: 'card' },
    el('h2', {}, 'Privacidade e dados'),
    el('p', { class: 'linha' }, 'Escolha o que compartilhar com a Ford, veja uma cópia dos seus dados ou exclua a conta.'),
    el('button', { type: 'button', class: 'btn btn-ghost btn-full', onclick: () => telaPrivacidade() }, 'Abrir privacidade'));
}

async function telaPrivacidade() {
  const payload = await exigirSessao(['cliente']);
  if (!payload) return encerrarSessao('expirou');
  const r = await api('GET', '/v1/me/consents', sessao.token);
  if (r.status === 401) return encerrarSessao('expirou');
  cabecalhoInterno('Privacidade e dados', 'Você decide o que compartilhar', () => telaCliente());
  iniciarTimerSessao(payload);
  const body = el('div', { class: 'body' });
  document.getElementById('corpo').append(body);
  if (r.status !== 200) return body.append(el('div', { class: 'alert alert-error' }, r.erro));

  let dados = r.dados;
  const listaHist = el('ol', { class: 'hist' });
  const desenharHistorico = () => {
    listaHist.innerHTML = '';
    if (!dados.historico.length) return listaHist.append(el('li', {}, el('span', { class: 'quando' }, 'Nenhum registro.')));
    dados.historico.slice(0, 8).forEach(h => listaHist.append(el('li', {},
      el('span', {}, FINALIDADES[h.finalidade].titulo),
      el('span', { class: 'pill ' + (h.concedido ? 'concedido' : 'revogado') }, h.concedido ? 'Autorizado' : 'Retirado'),
      el('span', { class: 'quando' }, `${new Date(h.em).toLocaleString('pt-BR')}, ${h.canal === 'app' ? 'pelo app' : 'no cadastro'}, política ${h.versao}`))));
  };

  const cardConsent = el('section', { class: 'card' }, el('h2', {}, 'O que você compartilha'));
  Object.entries(FINALIDADES).forEach(([f, info]) => {
    const chave = el('button', { type: 'button', class: 'switch', role: 'switch', 'aria-checked': String(dados.atual[f]), 'aria-label': info.titulo });
    const salvo = el('span', { class: 'salvo', role: 'status' });
    chave.addEventListener('click', async () => {
      const novo = chave.getAttribute('aria-checked') !== 'true';
      chave.disabled = true;
      const rr = await api('PUT', '/v1/me/consents', sessao.token, { corpo: { [f]: novo } });
      chave.disabled = false;
      if (rr.status === 401) return encerrarSessao('expirou');
      if (rr.status !== 200) { salvo.classList.add('erro'); salvo.textContent = rr.erro; return; }
      dados = rr.dados;
      chave.setAttribute('aria-checked', String(dados.atual[f]));
      salvo.classList.remove('erro');
      salvo.textContent = `${novo ? 'Autorizado' : 'Retirado'} às ${new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}`;
      desenharHistorico();
    });
    cardConsent.append(el('div', { class: 'switch-row' }, el('div', {}, el('strong', {}, info.titulo), el('span', {}, info.desc), salvo), chave));
  });

  body.append(
    el('p', { class: 'muted' }, `Cada item só é usado com a sua autorização, e a mudança vale na hora. Política de privacidade versão ${dados.politica_versao}.`),
    cardConsent,
    el('section', { class: 'card' }, el('h2', {}, 'Registro das suas escolhas'), listaHist),
    el('section', { class: 'card' }, el('h2', {}, 'Por quanto tempo guardamos'),
      el('dl', { class: 'detalhes' }, RETENCAO.map(([k, v]) => el('div', {}, el('dt', {}, k), el('dd', {}, v))))),
    el('section', { class: 'card' },
      el('h2', {}, 'Seus direitos'),
      el('p', { class: 'linha' }, 'Pela LGPD, você pode acessar seus dados, levá-los para outro serviço e pedir a exclusão da conta.'),
      el('div', { class: 'pilha' },
        el('button', { type: 'button', class: 'btn btn-ghost', onclick: () => telaExportacao() }, 'Ver e copiar meus dados'),
        el('button', { type: 'button', class: 'btn btn-ghost perigo', onclick: () => telaExclusao() }, 'Excluir minha conta'))),
    el('p', { class: 'muted' }, `Dúvidas sobre seus dados: fale com o encarregado (DPO) em ${CONTATO_DPO}.`));
  desenharHistorico();
}

async function telaExportacao() {
  const payload = await exigirSessao(['cliente']);
  if (!payload) return encerrarSessao('expirou');
  const r = await api('GET', '/v1/me/data-export', sessao.token);
  if (r.status === 401) return encerrarSessao('expirou');
  cabecalhoInterno('Meus dados', 'Cópia completa em JSON', () => telaPrivacidade());
  iniciarTimerSessao(payload);
  const body = el('div', { class: 'body' });
  document.getElementById('corpo').append(body);
  if (r.status !== 200) return body.append(el('div', { class: 'alert alert-error' }, r.erro));

  const texto = JSON.stringify(r.dados, null, 2);
  const btn = el('button', { type: 'button', class: 'btn btn-primary' }, 'Copiar dados');
  btn.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(texto); btn.textContent = 'Dados copiados'; }
    catch { btn.textContent = 'Não foi possível copiar'; }
    setTimeout(() => (btn.textContent = 'Copiar dados'), 1800);
  });
  body.append(
    el('p', { class: 'muted' }, 'Tudo o que está ligado à sua conta: cadastro, veículos, agendamentos e consentimentos, num formato que outro serviço consegue ler.'),
    el('pre', { class: 'export', tabindex: '0', 'aria-label': 'Seus dados em JSON' }, texto),
    btn,
    el('p', { class: 'nota' }, r.dados.nao_incluido));
}

async function telaExclusao() {
  const payload = await exigirSessao(['cliente']);
  if (!payload) return encerrarSessao('expirou');
  cabecalhoInterno('Excluir conta', 'Esta ação não pode ser desfeita', () => telaPrivacidade());
  iniciarTimerSessao(payload);

  const senha = el('input', { id: 'senhaExclusao', type: 'password', autocomplete: 'current-password', maxlength: String(CONFIG.SENHA_MAX) });
  const aceite = el('input', { type: 'checkbox', id: 'aceiteExclusao' });
  const msg = el('div', { role: 'alert' });
  const btn = el('button', { type: 'submit', class: 'btn btn-danger' }, 'Excluir minha conta');
  btn.disabled = true;
  aceite.addEventListener('change', () => { btn.disabled = !aceite.checked; });

  const form = el('form', { class: 'body', novalidate: '' },
    el('section', { class: 'card' },
      el('h2', {}, 'O que acontece'),
      el('ul', { class: 'lista-simples' },
        el('li', {}, 'Seu nome, e-mail e senha são apagados.'),
        el('li', {}, 'Seus veículos deixam de estar ligados a você. O histórico de serviços continua com o veículo, sem os seus dados.'),
        el('li', {}, 'Agendamentos em aberto são cancelados, e as observações que você escreveu são apagadas.'),
        el('li', {}, 'Seus consentimentos são retirados, e a concessionária não pode mais entrar em contato.'))),
    el('div', { class: 'field' }, el('label', { for: 'senhaExclusao' }, 'Digite sua senha para confirmar'), senha),
    el('label', { class: 'check', for: 'aceiteExclusao' }, aceite, el('span', {}, 'Entendo que a exclusão é permanente.')),
    msg, btn,
    el('p', { class: 'nota' }, 'No protótipo, recarregue a página para restaurar a conta de teste.'));

  form.addEventListener('submit', async ev => {
    ev.preventDefault();
    msg.innerHTML = '';
    if (!senha.value) { msg.append(el('div', { class: 'alert alert-error' }, 'Digite sua senha para confirmar.')); return senha.focus(); }
    btn.disabled = true;
    btn.textContent = 'Excluindo...';
    const r = await api('POST', '/v1/me/deletion', sessao.token, { corpo: { senha: senha.value } });
    senha.value = '';
    if (r.status === 200) return encerrarSessao('excluida');
    if (r.status === 401) return encerrarSessao('expirou');
    btn.disabled = !aceite.checked;
    btn.textContent = 'Excluir minha conta';
    msg.append(el('div', { class: 'alert alert-error' }, r.erro));
  });
  document.getElementById('corpo').append(form);
}

/* =========================================================
   23. MONITORAMENTO: regras de alerta, métricas e painel
   Cada evento do log passa pelas regras. Quando uma regra atinge o limite
   dentro da janela de tempo, abre um alerta (incidente) com as evidências.
   ========================================================= */
const SEVERIDADES = { critica: 'Crítica', alta: 'Alta', media: 'Média' };

const REGRAS_ALERTA = [
  { id: 'ALR-01', nome: 'Falhas de login repetidas na mesma conta', dominio: 'Autenticação', severidade: 'media',
    eventos: ['auth.login.failure'], chave: e => `${e.user} (${e.account_ref})`, limite: 3, janelaMin: 5,
    acao: 'Acompanhar a conta. O bloqueio automático acontece na 5ª falha.' },
  { id: 'ALR-02', nome: 'Conta bloqueada por força bruta', dominio: 'Autenticação', severidade: 'alta',
    eventos: ['auth.account.lockout'], chave: e => `${e.user} (${e.account_ref})`, limite: 1, janelaMin: 60,
    acao: 'Confirmar com o titular por outro canal, verificar a origem das tentativas e exigir troca de senha se houver login bem-sucedido depois.' },
  { id: 'ALR-03', nome: 'Password spraying: várias contas a partir da mesma origem', dominio: 'Autenticação', severidade: 'alta',
    eventos: ['auth.login.failure'], chave: e => e.ip, distinto: e => e.account_ref, limite: 3, janelaMin: 5,
    acao: 'Bloquear o IP de origem no WAF e revisar os logins bem-sucedidos vindos dele.' },
  { id: 'ALR-04', nome: 'Token JWT adulterado ou forjado', dominio: 'API', severidade: 'critica',
    eventos: ['api.auth.rejected'], filtro: e => ['signature_mismatch', 'alg_not_allowed', 'malformed', 'invalid_claims'].includes(e.reason),
    chave: e => e.ip, limite: 1, janelaMin: 60,
    acao: 'Tratar como tentativa de invasão. Se houver suspeita de vazamento da chave de assinatura, rotacionar a chave, o que invalida todos os tokens.' },
  { id: 'ALR-05', nome: 'Acesso a dado de outro cliente (BOLA/IDOR)', dominio: 'API', severidade: 'alta',
    eventos: ['api.authz.bola_attempt'], chave: e => e.user_id, limite: 1, janelaMin: 60,
    acao: 'Encerrar as sessões do usuário, revisar os acessos dele nas últimas 24 horas e confirmar que nenhum dado foi devolvido.' },
  { id: 'ALR-06', nome: 'Tentativas de acesso fora do perfil', dominio: 'API', severidade: 'alta',
    eventos: ['access.denied'], chave: e => e.user_id, limite: 2, janelaMin: 10,
    acao: 'Verificar se a conta foi comprometida ou se é abuso interno. Revisar as permissões do perfil.' },
  { id: 'ALR-07', nome: 'Excesso de requisições (rate limit)', dominio: 'API', severidade: 'media',
    eventos: ['api.rate_limited'], chave: e => e.user_id, limite: 1, janelaMin: 10,
    acao: 'Separar bug do app (requisição em loop) de abuso. Se for abuso, bloquear a origem temporariamente.' },
  { id: 'ALR-08', nome: 'Leitura em massa de leads (extração de dados do modelo)', dominio: 'ML', severidade: 'alta',
    eventos: ['data.access'], filtro: e => e.route === '/v1/analytics/leads', chave: e => e.user_id, limite: 5, janelaMin: 5,
    acao: 'Suspender o acesso do usuário ao endpoint de leads e confirmar com o gestor se a demanda é legítima.' },
  { id: 'ALR-09', nome: 'Perfil de usuário alterado', dominio: 'Administração', severidade: e => (e.to === 'admin' ? 'alta' : 'media'),
    eventos: ['admin.user.role_changed'], chave: e => e.target_user, limite: 1, janelaMin: 60,
    acao: 'Confirmar a mudança com o administrador que a fez e com o gestor do usuário. Mudança não autorizada indica conta de admin comprometida.' },
  { id: 'ALR-10', nome: 'Cache local do app adulterado', dominio: 'Mobile', severidade: 'alta',
    eventos: ['storage.cache.integrity_fail'], chave: e => e.ip, limite: 1, janelaMin: 60,
    acao: 'Aparelho possivelmente comprometido (root, jailbreak ou malware). Encerrar as sessões e orientar a reinstalação do app.' },
  { id: 'ALR-11', nome: 'Telemetria IoT rejeitada', dominio: 'IoT', severidade: 'alta',
    eventos: ['iot.telemetry.rejected'], chave: e => e.device_id, limite: 1, janelaMin: 30,
    acao: 'Pôr o módulo telemático em quarentena (parar de aceitar dados dele). Se a assinatura for inválida, revogar a credencial do dispositivo.' },
  { id: 'ALR-12', nome: 'Exclusão de conta pedida com senha errada', dominio: 'Privacidade', severidade: 'media',
    eventos: ['privacy.deletion.reauth_failed'], chave: e => e.user_id, limite: 1, janelaMin: 30,
    acao: 'Possível sessão sequestrada. Avisar o titular por outro canal e encerrar as sessões se houver nova tentativa.' }
];

const NIVEL_POR_SEVERIDADE = { critica: 'CRITICAL', alta: 'CRITICAL', media: 'WARN' };
// Eventos gerados pelo lado da segurança não vêm do aparelho: origem própria e sem IP do cliente
const ORIGEM_MOTOR = { source: 'motor-alertas', ip: undefined };
const ORIGEM_CONSOLE = { source: 'console-resposta', ip: undefined };

const Monitor = {
  alertas: [],
  janelas: new Map(), // "regra|chave" -> [{ t, trace, valor }]
  seq: 0,

  processar(e) {
    if (e.event.startsWith('alert.')) return; // alertas não disparam alertas
    for (const r of REGRAS_ALERTA) {
      if (!r.eventos.includes(e.event)) continue;
      if (r.filtro && !r.filtro(e)) continue;
      const chave = String(r.chave(e) || 'desconhecido');
      const k = r.id + '|' + chave;
      const agora = Date.parse(e.timestamp);
      const janela = (this.janelas.get(k) || []).filter(x => agora - x.t <= r.janelaMin * 60000);
      janela.push({ t: agora, trace: e.trace_id, valor: r.distinto ? r.distinto(e) : null });
      this.janelas.set(k, janela);
      const contagem = r.distinto ? new Set(janela.map(x => x.valor)).size : janela.length;
      if (contagem < r.limite) continue;

      // Já existe alerta aberto para a mesma regra e chave: soma a ocorrência (deduplicação)
      const aberto = this.alertas.find(a => a.regra === r.id && a.chave === chave && alertaAberto(a));
      if (aberto) {
        aberto.ocorrencias += 1;
        aberto.ultimo = e.timestamp;
        if (aberto.evidencias.length < 10) aberto.evidencias.push(e.trace_id);
        continue;
      }
      const severidade = typeof r.severidade === 'function' ? r.severidade(e) : r.severidade;
      this.seq += 1;
      const alerta = {
        id: 'INC-' + String(this.seq).padStart(4, '0'), regra: r.id, nome: r.nome, dominio: r.dominio, severidade, chave,
        primeiro: new Date(janela[0].t).toISOString(), ultimo: e.timestamp, ocorrencias: janela.length,
        evidencias: janela.slice(-10).map(x => x.trace), acao: r.acao, status: 'aberto',
        // Campos do evento que as ações de resposta precisam (sem dado pessoal em claro)
        contexto: { user_id: e.user_id, user: e.user, account_ref: e.account_ref, ip: e.ip, device_id: e.device_id,
                    target_user: e.target_user, from: e.from, to: e.to, reason: e.reason },
        resposta: { passos: {}, fases: {}, classificacao: null, encerradoEm: null }
      };
      this.alertas.unshift(alerta);
      Log.registrar('alert.triggered', NIVEL_POR_SEVERIDADE[severidade], {
        ...ORIGEM_MOTOR, alert_id: alerta.id, rule_id: r.id, severity: severidade, domain: r.dominio, key: chave, occurrences: alerta.ocorrencias
      });
    }
    desenharAlertas();
    agendarPainel();
  }
};

// --- Lista de alertas
const hora = iso => new Date(iso).toLocaleTimeString('pt-BR');

function desenharAlertas() {
  const alvo = document.getElementById('listaAlertas');
  if (!alvo) return;
  const abertos = Monitor.alertas.filter(alertaAberto).length;
  const badge = document.getElementById('badgeAlertas');
  badge.textContent = String(abertos);
  badge.hidden = abertos === 0;

  const rolagem = alvo.scrollTop;
  if (incidenteAberto) {
    const inc = Monitor.alertas.find(x => x.id === incidenteAberto);
    if (inc) { desenharIncidente(alvo, inc); alvo.scrollTop = rolagem; return; }
    incidenteAberto = null;
  }
  alvo.innerHTML = '';
  if (!Monitor.alertas.length) {
    alvo.append(el('p', { class: 'empty' }, 'Nenhum alerta. Rode uma simulação na aba Ataques para ver as regras disparando.'));
    return;
  }
  Monitor.alertas.forEach(a => {
    alvo.append(el('article', { class: 'alerta sev-' + a.severidade },
      el('div', { class: 'alerta-topo' },
        el('span', { class: 'alerta-id' }, a.id),
        el('span', { class: 'sev ' + a.severidade }, SEVERIDADES[a.severidade]),
        el('span', { class: 'estado st-' + a.status }, STATUS_INCIDENTE[a.status])),
      el('h4', {}, a.nome),
      el('p', { class: 'meta' }, `${a.regra}, domínio ${a.dominio}, chave ${a.chave}`),
      el('p', { class: 'meta' }, `${plural(a.ocorrencias, 'ocorrência', 'ocorrências')}, de ${hora(a.primeiro)} a ${hora(a.ultimo)}`),
      el('p', { class: 'acao' }, el('strong', {}, 'Ação recomendada: '), a.acao),
      el('p', { class: 'evid' }, 'Evidências (trace_id): ' + a.evidencias.map(t => t.slice(0, 8)).join(', ')),
      el('div', { class: 'alerta-rodape' },
        el('button', { type: 'button', class: 'btn-sm' + (alertaAberto(a) ? '' : ' ghost'),
          onclick: () => { incidenteAberto = a.id; desenharAlertas(); alvo.scrollTop = 0; } },
          alertaAberto(a) ? 'Responder' : 'Ver resposta'))));
  });
  alvo.scrollTop = rolagem;
}

// --- Painel de métricas (janela dos últimos 15 minutos)
const JANELA_PAINEL_MIN = 15;
let painelAgendado = false;
function agendarPainel() {
  if (painelAgendado) return;
  painelAgendado = true;
  requestAnimationFrame(() => { painelAgendado = false; desenharPainel(); });
}

function dominioDoEvento(e) {
  const ev = e.event;
  if (ev.startsWith('iot.')) return 'IoT';
  if (ev.startsWith('lead.') || (ev === 'data.access' && String(e.route || '').startsWith('/v1/analytics'))) return 'ML e análise';
  if (ev.startsWith('auth.')) return 'Autenticação';
  if (ev.startsWith('storage.') || ev === 'app.start') return 'Mobile';
  if (ev.startsWith('privacy.') || ev === 'data.sensitive.read' || ev === 'data.location.used') return 'Privacidade';
  if (ev.startsWith('admin.')) return 'Administração';
  if (ev.startsWith('alert.')) return 'Alertas';
  if (ev.startsWith('ir.')) return 'Resposta a incidentes';
  return 'API';
}

function desenharPainel() {
  const alvo = document.getElementById('painelMetricas');
  if (!alvo || document.getElementById('viewPainel').hidden) return;
  const agora = Date.now();
  const recentes = Log.itens.filter(e => agora - Date.parse(e.timestamp) <= JANELA_PAINEL_MIN * 60000);
  const conta = f => recentes.filter(f).length;
  const abertos = Monitor.alertas.filter(alertaAberto);

  const kpis = [
    ['Eventos', recentes.length, ''],
    ['Logins com falha', conta(e => e.event === 'auth.login.failure'), 'warn'],
    ['Acessos negados (401/403)', conta(e => e.status === 401 || e.status === 403), 'warn'],
    ['Bloqueios por limite (429)', conta(e => e.event === 'api.rate_limited'), 'warn'],
    ['Telemetria rejeitada', conta(e => e.event === 'iot.telemetry.rejected'), 'warn'],
    ['Alertas abertos', abertos.length, abertos.some(a => a.severidade !== 'media') ? 'bad' : '']
  ];

  // Linha do tempo: eventos por minuto, empilhados por nível
  const buckets = Array.from({ length: JANELA_PAINEL_MIN }, () => ({ INFO: 0, WARN: 0, CRITICAL: 0 }));
  recentes.forEach(e => {
    const idx = JANELA_PAINEL_MIN - 1 - Math.floor((agora - Date.parse(e.timestamp)) / 60000);
    if (idx >= 0 && idx < JANELA_PAINEL_MIN) buckets[idx][e.level in buckets[idx] ? e.level : 'INFO'] += 1;
  });
  const max = Math.max(1, ...buckets.map(b => b.INFO + b.WARN + b.CRITICAL));
  const W = 600, H = 150, larg = W / JANELA_PAINEL_MIN;
  const svgNS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${W} ${H + 22}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Eventos por minuto nos últimos 15 minutos');
  buckets.forEach((b, i) => {
    let y = H;
    [['INFO', 'var(--ok)'], ['WARN', 'var(--signal)'], ['CRITICAL', 'var(--danger)']].forEach(([nivel, cor]) => {
      const h = (b[nivel] / max) * (H - 10);
      if (!h) return;
      y -= h;
      const r = document.createElementNS(svgNS, 'rect');
      r.setAttribute('x', String(i * larg + 4)); r.setAttribute('y', String(y));
      r.setAttribute('width', String(larg - 8)); r.setAttribute('height', String(h));
      r.setAttribute('rx', '2'); r.setAttribute('fill', cor);
      svg.appendChild(r);
    });
  });
  [[0, `-${JANELA_PAINEL_MIN} min`], [W, 'agora']].forEach(([x, texto]) => {
    const t = document.createElementNS(svgNS, 'text');
    t.setAttribute('x', String(x)); t.setAttribute('y', String(H + 16));
    t.setAttribute('text-anchor', x ? 'end' : 'start'); t.setAttribute('class', 'eixo');
    t.textContent = texto;
    svg.appendChild(t);
  });

  const porDominio = {};
  recentes.forEach(e => { const d = dominioDoEvento(e); porDominio[d] = (porDominio[d] || 0) + 1; });
  const porEvento = {};
  recentes.forEach(e => { porEvento[e.event] = (porEvento[e.event] || 0) + 1; });
  const barrasDe = obj => {
    const itens = Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, 7);
    const topo = Math.max(1, ...itens.map(x => x[1]));
    return itens.length
      ? el('ul', { class: 'mini-barras' }, itens.map(([k, v]) => el('li', {},
          el('span', { class: 'rot' }, k), el('span', { class: 'num' }, String(v)),
          el('span', { class: 'trilho' }, el('span', { style: `width:${(v / topo) * 100}%` })))))
      : el('p', { class: 'empty' }, 'Sem eventos na janela.');
  };

  alvo.innerHTML = '';
  alvo.append(
    el('p', { class: 'painel-sub' }, `Últimos ${JANELA_PAINEL_MIN} minutos, atualizado em tempo real`),
    el('div', { class: 'kpis' }, kpis.map(([rot, val, cls]) => el('div', { class: 'kpi-card ' + cls }, el('b', {}, String(val)), el('span', {}, rot)))),
    el('section', { class: 'painel-bloco' }, el('h4', {}, 'Eventos por minuto'), svg,
      el('div', { class: 'legenda' },
        el('span', { class: 'l-info' }, 'INFO'), el('span', { class: 'l-warn' }, 'WARN'), el('span', { class: 'l-crit' }, 'CRITICAL'))),
    el('div', { class: 'painel-duplo' },
      el('section', { class: 'painel-bloco' }, el('h4', {}, 'Por domínio'), barrasDe(porDominio)),
      el('section', { class: 'painel-bloco' }, el('h4', {}, 'Eventos mais frequentes'), barrasDe(porEvento))),
    el('section', { class: 'painel-bloco' }, el('h4', {}, 'Alertas abertos por severidade'),
      el('div', { class: 'sev-linha' }, Object.keys(SEVERIDADES).map(s =>
        el('span', { class: 'sev ' + s }, `${SEVERIDADES[s]}: ${abertos.filter(a => a.severidade === s).length}`)))));
}
setInterval(agendarPainel, 30000); // a janela de 15 min anda mesmo sem eventos novos

/* =========================================================
   24. INGESTÃO DE TELEMETRIA IoT (módulo telemático do veículo -> broker MQTT/TLS -> API)
   Cada mensagem é assinada com HMAC pela chave do dispositivo.
   A API confere assinatura, VIN, horário (anti-replay) e coerência do odômetro.
   ========================================================= */
const DISPOSITIVOS = [
  { id: 'tcu-5001', veiculoId: 'v-5001' },
  { id: 'tcu-5002', veiculoId: 'v-5002' }
];
// No veículo real, a chave fica no elemento seguro do módulo telemático e nunca sai dele
const chavesDispositivos = new Map();
const ultimaLeitura = new Map();
const CAMPOS_TELEMETRIA = ['device_id', 'vin', 'km', 'ts', 'assinatura'];
const IP_BROKER = '10.20.0.15';

async function chaveDispositivo(id) {
  if (!chavesDispositivos.has(id))
    chavesDispositivos.set(id, await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']));
  return chavesDispositivos.get(id);
}
const mensagemCanonica = m => `${m.device_id}|${m.vin}|${m.km}|${m.ts}`;
async function assinarTelemetria(m, chave) {
  return b64url(await crypto.subtle.sign('HMAC', chave, enc.encode(mensagemCanonica(m))));
}

async function receberTelemetria(m) {
  const base = { source: 'broker-mqtt', ip: IP_BROKER };
  const rejeitar = (motivo, extra = {}) => {
    Log.registrar('iot.telemetry.rejected', 'WARN', { ...base, device_id: (m && m.device_id) || 'desconhecido', reason: motivo, ...extra });
    return { aceita: false, motivo };
  };
  // 1) Esquema: só os campos esperados, com os tipos certos
  if (!m || typeof m !== 'object' || Object.keys(m).some(k => !CAMPOS_TELEMETRIA.includes(k)) ||
      typeof m.device_id !== 'string' || typeof m.vin !== 'string' || !Number.isFinite(m.km) || typeof m.ts !== 'string' || typeof m.assinatura !== 'string')
    return rejeitar('invalid_schema');
  // 2) Dispositivo provisionado?
  const d = DISPOSITIVOS.find(x => x.id === m.device_id);
  if (!d) return rejeitar('unknown_device');
  if (QUARENTENA.has(d.id)) { // contenção de incidente: dados do dispositivo ignorados até a análise
    Log.registrar('iot.telemetry.quarantined', 'INFO', { ...base, device_id: d.id, reason: 'device_in_quarantine' });
    return { aceita: false, motivo: 'quarentena' };
  }
  const v = VEICULOS_DB.find(x => x.id === d.veiculoId);
  // 3) Assinatura HMAC do dispositivo
  let assinaturaOk = false;
  try { assinaturaOk = await crypto.subtle.verify('HMAC', await chaveDispositivo(d.id), b64urlParaBytes(m.assinatura), enc.encode(mensagemCanonica(m))); }
  catch { assinaturaOk = false; }
  if (!assinaturaOk) return rejeitar('invalid_signature');
  // 4) O VIN precisa ser o do veículo em que o dispositivo foi instalado
  if (m.vin !== v.vin) return rejeitar('vin_mismatch');
  // 5) Anti-replay: horário dentro de 5 minutos
  if (!(Math.abs(Date.now() - Date.parse(m.ts)) <= 5 * 60000)) return rejeitar('timestamp_out_of_window');
  // 6) Coerência física: odômetro não volta e não salta
  const anterior = ultimaLeitura.get(d.id) || { km: v.km, ts: v.telemetriaEm };
  if (m.km < anterior.km) return rejeitar('odometer_rollback', { km_previous: anterior.km, km_received: m.km });
  const horas = Math.max((Date.parse(m.ts) - Date.parse(anterior.ts)) / 3600000, 1 / 60);
  if ((m.km - anterior.km) / horas > 250) return rejeitar('implausible_speed', { km_delta: m.km - anterior.km });
  // 7) LGPD: sem consentimento de telemetria, a leitura é descartada
  if (!consentimentosDe(v.ownerId).telemetria) {
    Log.registrar('iot.telemetry.discarded', 'INFO', { ...base, device_id: d.id, reason: 'no_consent' });
    return { aceita: false, motivo: 'sem_consentimento' };
  }
  v.km = m.km;
  v.telemetriaEm = m.ts;
  ultimaLeitura.set(d.id, { km: m.km, ts: m.ts });
  Log.registrar('iot.telemetry.accepted', 'INFO', { ...base, device_id: d.id, vehicle_id: v.id, km_delta: m.km - anterior.km, channel: 'mqtts' });
  return { aceita: true };
}

/* =========================================================
   25. RESPOSTA A INCIDENTES (SANS PICERL)
   Preparação -> Identificação -> Contenção -> Erradicação -> Recuperação.
   Cada regra de alerta aponta para um playbook. As ações de contenção agem de verdade no sistema.
   ========================================================= */
const FASES = [
  ['preparacao', 'Preparação'], ['identificacao', 'Identificação'], ['contencao', 'Contenção'],
  ['erradicacao', 'Erradicação'], ['recuperacao', 'Recuperação']
];
const STATUS_INCIDENTE = {
  aberto: 'Aberto', analise: 'Em análise', contido: 'Contido', erradicado: 'Erradicado',
  resolvido: 'Resolvido', falso_positivo: 'Falso positivo'
};
function alertaAberto(a) { return a.status !== 'resolvido' && a.status !== 'falso_positivo'; }
let incidenteAberto = null;

// --- Estado das contenções (lido pela API, pelo login e pela ingestão IoT)
const IPS_BLOQUEADOS = new Map(); // ip -> bloqueado até (ms)
const SUSPENSOES = new Map();     // userId -> Set(permissões suspensas)
const QUARENTENA = new Set();     // dispositivos IoT em quarentena
function ipBloqueado(ip = IP_ORIGEM) {
  const ate = IPS_BLOQUEADOS.get(ip);
  return Boolean(ate && ate > Date.now());
}
async function conferirSessaoAtual() {
  if (sessao && !(await verificarToken(sessao.token))) encerrarSessao('seguranca');
}
function usuarioDoAlerta(a) {
  if (a.regra === 'ALR-03') return null; // spraying: o alvo é a origem, não uma conta
  const c = a.contexto;
  if (c.account_ref) return USUARIOS.find(u => refConta(u.email) === c.account_ref) || null;
  if (c.user_id) return USUARIOS.find(u => u.id === c.user_id) || null;
  return null;
}
const nomeConta = u => (u ? mascararEmail(u.email) : 'conta não identificada');

// --- Ações de resposta (cada uma fica registrada no log com o id do incidente)
const Contencao = {
  registrar(a, acao, alvo, extra = {}) {
    Log.registrar('ir.action.executed', 'WARN', { ...ORIGEM_CONSOLE, incident_id: a.id, action: acao, target: alvo, ...extra });
  },
  async bloquearIp(a, ip, min = 30) {
    IPS_BLOQUEADOS.set(ip, Date.now() + min * 60000);
    this.registrar(a, 'block_ip', ip, { minutes: min });
    if (sessao && ip === IP_ORIGEM) encerrarSessao('seguranca');
    return `Origem ${ip} bloqueada por ${min} minutos. Login e API recusam qualquer requisição dela.`;
  },
  async liberarIp(a, ip) {
    IPS_BLOQUEADOS.delete(ip);
    this.registrar(a, 'unblock_ip', ip);
    return `Origem ${ip} liberada.`;
  },
  async bloquearConta(a, u, min = 30) {
    tentativas.set(u.email, { falhas: 0, bloqueadoAte: Date.now() + min * 60000 });
    u.versaoToken += 1;
    this.registrar(a, 'block_account', u.id, { minutes: min });
    await conferirSessaoAtual();
    return `Conta ${nomeConta(u)} bloqueada por ${min} minutos e sessões encerradas.`;
  },
  async liberarConta(a, u) {
    tentativas.delete(u.email);
    this.registrar(a, 'unblock_account', u.id);
    return `Conta ${nomeConta(u)} liberada.`;
  },
  async encerrarSessoes(a, u) {
    u.versaoToken += 1;
    this.registrar(a, 'revoke_sessions', u.id);
    await conferirSessaoAtual();
    return `Sessões de ${nomeConta(u)} encerradas. O próximo acesso exige login.`;
  },
  async suspender(a, userId, permissao) {
    if (!SUSPENSOES.has(userId)) SUSPENSOES.set(userId, new Set());
    SUSPENSOES.get(userId).add(permissao);
    this.registrar(a, 'suspend_permission', userId, { permission: permissao });
    return `Permissão ${permissao} suspensa para ${userId}.`;
  },
  async restaurar(a, userId, permissao) {
    if (SUSPENSOES.has(userId)) SUSPENSOES.get(userId).delete(permissao);
    this.registrar(a, 'restore_permission', userId, { permission: permissao });
    return `Permissão ${permissao} devolvida para ${userId}.`;
  },
  async quarentena(a, id) {
    QUARENTENA.add(id);
    this.registrar(a, 'quarantine_device', id);
    return `Dispositivo ${id} em quarentena. A API passa a descartar os dados dele.`;
  },
  async liberarQuarentena(a, id) {
    QUARENTENA.delete(id);
    this.registrar(a, 'release_device', id);
    return `Dispositivo ${id} fora da quarentena.`;
  },
  async reprovisionar(a, id) {
    chavesDispositivos.delete(id);
    await chaveDispositivo(id);
    ultimaLeitura.delete(id);
    this.registrar(a, 'rotate_device_credential', id);
    return `Credencial de ${id} revogada e chave nova gerada. Mensagens assinadas com a chave antiga passam a ser recusadas.`;
  },
  async rotacionarJWT(a) {
    chaveJWTAnterior = chaveJWT;
    await iniciarChaveJWT();
    this.registrar(a, 'rotate_jwt_key', 'api');
    if (sessao) encerrarSessao('seguranca');
    return 'Chave de assinatura do JWT rotacionada. Todos os tokens anteriores foram invalidados; os usuários precisam entrar de novo.';
  },
  async reverterPerfil(a, u, perfil) {
    const antes = u.perfil;
    u.perfil = perfil;
    u.versaoToken += 1;
    this.registrar(a, 'revert_role', u.id, { from: antes, to: perfil });
    await conferirSessaoAtual();
    return `Perfil de ${u.nome} revertido de ${PERFIS[antes].rotulo} para ${PERFIS[perfil].rotulo}.`;
  },
  async limparAparelho(a) {
    CacheSeguro.limpar();
    this.registrar(a, 'wipe_device_cache', 'aparelho');
    if (sessao) encerrarSessao('seguranca');
    return 'Cache local apagado e sessão do aparelho encerrada.';
  }
};

// --- Consultas usadas na Identificação
function resumoPorEvento(filtro) {
  const cont = {};
  Log.itens.filter(filtro).forEach(e => { cont[e.event] = (cont[e.event] || 0) + 1; });
  const itens = Object.entries(cont).sort((x, y) => y[1] - x[1]);
  return itens.length ? itens.map(([ev, n]) => `${n}× ${ev}`).join(', ') : 'nenhum evento';
}

// --- Preparação: o que já existe antes de qualquer incidente
const PREPARACAO_COMUM = [
  'Logs estruturados em JSON, com trace_id, em todos os eventos de segurança (seção 3).',
  '12 regras de alerta avaliadas em tempo real, com deduplicação (seção 23).',
  'Ações de contenção prontas neste console: bloquear origem ou conta, encerrar sessões, suspender permissão, quarentena de dispositivo e rotação de chaves.',
  'Papéis definidos: analista de plantão conduz, dono do sistema aprova mudanças, DPO avalia comunicação à ANPD e aos titulares.'
];

const decisao = (opcoes) => ({ id: 'id-classificar', fase: 'identificacao', tipo: 'decisao', texto: 'Classificar o alerta', opcoes });

const PLAYBOOKS = {
  'PB-01': {
    nome: 'Ataque a credenciais', regras: ['ALR-01', 'ALR-02', 'ALR-03', 'ALR-12'],
    preparacao: ['Bloqueio automático após 5 falhas; mensagem de erro que não revela se o e-mail existe.'],
    passos: [
      { id: 'id-eventos', fase: 'identificacao', tipo: 'check', texto: 'Revisar os eventos relacionados: quantas contas, quantas tentativas e de qual origem.' },
      { id: 'id-sucesso', fase: 'identificacao', tipo: 'acao', texto: 'Procurar login bem-sucedido da mesma origem depois das falhas',
        executar: async a => {
          const n = Log.itens.filter(e => e.event === 'auth.login.success' && e.ip === a.contexto.ip && Date.parse(e.timestamp) >= Date.parse(a.primeiro)).length;
          return n ? `${plural(n, 'login com sucesso', 'logins com sucesso')} da mesma origem depois das falhas. Verificar se foram do titular.` : 'Nenhum login com sucesso da mesma origem depois das falhas.';
        } },
      decisao(),
      { id: 'ct-conta', fase: 'contencao', tipo: 'acao', se: a => Boolean(usuarioDoAlerta(a)),
        texto: a => `Bloquear a conta ${nomeConta(usuarioDoAlerta(a))} por 30 minutos e encerrar as sessões`,
        executar: a => Contencao.bloquearConta(a, usuarioDoAlerta(a)) },
      { id: 'ct-ip', fase: 'contencao', tipo: 'acao', se: a => a.regra === 'ALR-03', perigo: true,
        texto: a => `Bloquear a origem ${a.contexto.ip} por 30 minutos`, executar: a => Contencao.bloquearIp(a, a.contexto.ip) },
      { id: 'er-titular', fase: 'erradicacao', tipo: 'check', texto: 'Confirmar com o titular por outro canal (e-mail ou SMS) e exigir troca de senha no próximo login.' },
      { id: 'er-waf', fase: 'erradicacao', tipo: 'check', se: a => a.regra === 'ALR-03', texto: 'Se a origem for externa, incluí-la de forma permanente na lista de bloqueio do WAF.' },
      { id: 'rc-conta', fase: 'recuperacao', tipo: 'acao', se: a => Boolean(usuarioDoAlerta(a)),
        texto: a => `Liberar a conta ${nomeConta(usuarioDoAlerta(a))} depois da confirmação do titular`, executar: a => Contencao.liberarConta(a, usuarioDoAlerta(a)) },
      { id: 'rc-ip', fase: 'recuperacao', tipo: 'acao', se: a => a.regra === 'ALR-03',
        texto: a => `Liberar a origem ${a.contexto.ip}`, executar: a => Contencao.liberarIp(a, a.contexto.ip) },
      { id: 'rc-observar', fase: 'recuperacao', tipo: 'check', texto: 'Manter a conta em observação por 24 horas (a regra ALR-01 continua ativa).' }
    ]
  },
  'PB-02': {
    nome: 'Token JWT forjado', regras: ['ALR-04'],
    preparacao: ['A API confere assinatura, algoritmo, validade e versão de cada token (seção 7).'],
    passos: [
      { id: 'id-eventos', fase: 'identificacao', tipo: 'check', texto: 'Revisar o motivo da recusa (assinatura inválida ou algoritmo não permitido) e a origem.' },
      { id: 'id-aceito', fase: 'identificacao', tipo: 'acao', texto: 'Verificar se algum token adulterado foi aceito',
        executar: async a => `Recusas desta origem: ${resumoPorEvento(e => e.event === 'api.auth.rejected' && e.ip === a.contexto.ip)}. Nenhuma requisição com token adulterado passou da autenticação.` },
      decisao(),
      { id: 'ct-ip', fase: 'contencao', tipo: 'acao', perigo: true, texto: a => `Bloquear a origem ${a.contexto.ip} por 30 minutos`,
        executar: a => Contencao.bloquearIp(a, a.contexto.ip) },
      { id: 'er-vazamento', fase: 'erradicacao', tipo: 'check', texto: 'Verificar se a chave de assinatura pode ter vazado (rodar o Trufflehog no repositório e revisar variáveis de ambiente).' },
      { id: 'er-chave', fase: 'erradicacao', tipo: 'acao', perigo: true, texto: 'Rotacionar a chave de assinatura do JWT (todos os usuários precisam entrar de novo)',
        executar: a => Contencao.rotacionarJWT(a) },
      { id: 'rc-ip', fase: 'recuperacao', tipo: 'acao', texto: a => `Liberar a origem ${a.contexto.ip}`, executar: a => Contencao.liberarIp(a, a.contexto.ip) },
      { id: 'rc-login', fase: 'recuperacao', tipo: 'check', texto: 'Confirmar que os usuários legítimos entram normalmente com tokens novos.' }
    ]
  },
  'PB-03': {
    nome: 'Acesso indevido a dados', regras: ['ALR-05', 'ALR-06', 'ALR-08'],
    preparacao: ['RBAC com menor privilégio e checagem de dono em cada recurso; leads pseudoanonimizados.'],
    passos: [
      { id: 'id-eventos', fase: 'identificacao', tipo: 'check', texto: 'Revisar os eventos relacionados: que recurso foi pedido e qual resposta a API deu.' },
      { id: 'id-historico', fase: 'identificacao', tipo: 'acao', texto: 'Levantar tudo o que o usuário fez na última hora',
        executar: async a => `Atividade de ${a.contexto.user_id} na última hora: ${resumoPorEvento(e => e.user_id === a.contexto.user_id && Date.now() - Date.parse(e.timestamp) <= 3600000)}.` },
      decisao(),
      { id: 'ct-sessoes', fase: 'contencao', tipo: 'acao', se: a => Boolean(usuarioDoAlerta(a)),
        texto: a => `Encerrar as sessões de ${nomeConta(usuarioDoAlerta(a))}`, executar: a => Contencao.encerrarSessoes(a, usuarioDoAlerta(a)) },
      { id: 'ct-suspender', fase: 'contencao', tipo: 'acao', se: a => a.regra === 'ALR-08',
        texto: 'Suspender a permissão de leitura de leads (leads:ler)', executar: a => Contencao.suspender(a, a.contexto.user_id, 'leads:ler') },
      { id: 'er-gestor', fase: 'erradicacao', tipo: 'check', texto: 'Confirmar com o gestor se a conta foi comprometida ou se é abuso interno. Se foi comprometida, exigir troca de senha.' },
      { id: 'er-lgpd', fase: 'erradicacao', tipo: 'check', texto: 'Com o DPO, avaliar se dados pessoais foram expostos e se é preciso comunicar a ANPD e os titulares (LGPD, art. 48).' },
      { id: 'rc-restaurar', fase: 'recuperacao', tipo: 'acao', se: a => a.regra === 'ALR-08',
        texto: 'Devolver a permissão depois da autorização do gestor', executar: a => Contencao.restaurar(a, a.contexto.user_id, 'leads:ler') },
      { id: 'rc-observar', fase: 'recuperacao', tipo: 'check', texto: 'Manter o usuário em observação por 7 dias.' }
    ]
  },
  'PB-04': {
    nome: 'Alteração de privilégio', regras: ['ALR-09'],
    preparacao: ['Toda mudança de perfil fica na trilha de auditoria e derruba as sessões do usuário alterado.'],
    passos: [
      { id: 'id-eventos', fase: 'identificacao', tipo: 'check', texto: 'Conferir quem alterou, qual conta e de qual perfil para qual.' },
      decisao({ vp: 'Mudança não autorizada', fp: 'Mudança autorizada (encerrar)' }),
      { id: 'ct-reverter', fase: 'contencao', tipo: 'acao',
        texto: a => `Reverter ${a.contexto.target_user} para o perfil anterior (${PERFIS[a.contexto.from] ? PERFIS[a.contexto.from].rotulo : a.contexto.from})`,
        executar: a => Contencao.reverterPerfil(a, USUARIOS.find(u => u.id === a.contexto.target_user), a.contexto.from) },
      { id: 'ct-admin', fase: 'contencao', tipo: 'acao', perigo: true, texto: a => `Encerrar as sessões do administrador que fez a mudança (${a.contexto.user_id})`,
        executar: a => Contencao.encerrarSessoes(a, USUARIOS.find(u => u.id === a.contexto.user_id)) },
      { id: 'er-admin', fase: 'erradicacao', tipo: 'check', texto: 'Trocar a senha do administrador e revisar as outras ações dele na trilha de auditoria.' },
      { id: 'rc-perfil', fase: 'recuperacao', tipo: 'check', texto: 'Confirmar com o gestor o perfil correto e registrar a aprovação.' }
    ]
  },
  'PB-05': {
    nome: 'Abuso de API', regras: ['ALR-07'],
    preparacao: ['Rate limit de 30 requisições por minuto por usuário, com resposta 429.'],
    passos: [
      { id: 'id-eventos', fase: 'identificacao', tipo: 'check', texto: 'Separar bug do app (requisição em loop) de abuso deliberado.' },
      decisao(),
      { id: 'ct-conta', fase: 'contencao', tipo: 'acao', se: a => Boolean(usuarioDoAlerta(a)),
        texto: a => `Suspender ${nomeConta(usuarioDoAlerta(a))} por 30 minutos`, executar: a => Contencao.bloquearConta(a, usuarioDoAlerta(a)) },
      { id: 'er-causa', fase: 'erradicacao', tipo: 'check', texto: 'Se for bug, abrir correção no app; se for abuso, manter o bloqueio e rever o limite.' },
      { id: 'rc-conta', fase: 'recuperacao', tipo: 'acao', se: a => Boolean(usuarioDoAlerta(a)),
        texto: a => `Liberar ${nomeConta(usuarioDoAlerta(a))}`, executar: a => Contencao.liberarConta(a, usuarioDoAlerta(a)) }
    ]
  },
  'PB-06': {
    nome: 'Aparelho comprometido', regras: ['ALR-10'],
    preparacao: ['Cache local cifrado com AES-256-GCM: qualquer alteração é detectada pela tag de autenticação.'],
    passos: [
      { id: 'id-eventos', fase: 'identificacao', tipo: 'check', texto: 'Conferir o evento de integridade: o cache cifrado foi alterado fora do app.' },
      decisao(),
      { id: 'ct-aparelho', fase: 'contencao', tipo: 'acao', perigo: true, texto: 'Apagar o cache do aparelho e encerrar a sessão', executar: a => Contencao.limparAparelho(a) },
      { id: 'er-reinstalar', fase: 'erradicacao', tipo: 'check', texto: 'Orientar o usuário a remover o app, verificar root ou jailbreak e reinstalar pela loja oficial.' },
      { id: 'rc-chave', fase: 'recuperacao', tipo: 'check', texto: 'Confirmar o novo login: o app gera uma chave AES nova e recria o cache.' }
    ]
  },
  'PB-07': {
    nome: 'Telemetria IoT adulterada', regras: ['ALR-11'],
    preparacao: ['Mensagens assinadas com HMAC pelo módulo telemático, com checagem de VIN, horário e odômetro.'],
    passos: [
      { id: 'id-eventos', fase: 'identificacao', tipo: 'check', texto: 'Conferir os motivos da rejeição (assinatura inválida, odômetro voltando, VIN diferente).' },
      { id: 'id-leituras', fase: 'identificacao', tipo: 'acao', texto: 'Levantar as leituras do dispositivo',
        executar: async a => `Leituras de ${a.contexto.device_id}: ${resumoPorEvento(e => e.device_id === a.contexto.device_id && e.event.startsWith('iot.'))}.` },
      decisao(),
      { id: 'ct-quarentena', fase: 'contencao', tipo: 'acao', texto: a => `Pôr o módulo ${a.contexto.device_id} em quarentena`,
        executar: a => Contencao.quarentena(a, a.contexto.device_id) },
      { id: 'er-credencial', fase: 'erradicacao', tipo: 'acao', texto: 'Revogar a credencial do dispositivo e gerar uma chave nova (após inspeção na concessionária)',
        executar: a => Contencao.reprovisionar(a, a.contexto.device_id) },
      { id: 'er-km', fase: 'erradicacao', tipo: 'check', texto: 'Corrigir a quilometragem do veículo com a leitura do painel feita na concessionária.' },
      { id: 'rc-liberar', fase: 'recuperacao', tipo: 'acao', texto: a => `Retirar ${a.contexto.device_id} da quarentena`,
        executar: a => Contencao.liberarQuarentena(a, a.contexto.device_id) },
      { id: 'rc-observar', fase: 'recuperacao', tipo: 'check', texto: 'Acompanhar as leituras do dispositivo por 24 horas.' }
    ]
  }
};

function playbookDo(a) { return Object.entries(PLAYBOOKS).find(([, pb]) => pb.regras.includes(a.regra)); }
function passosDaFase(a, fase) {
  const [, pb] = playbookDo(a);
  return pb.passos.filter(p => p.fase === fase && (!p.se || p.se(a)));
}
function faseConcluida(a, fase) {
  if (fase === 'preparacao') return true;
  const passos = passosDaFase(a, fase);
  return passos.length > 0 && passos.every(p => a.resposta.passos[p.id]);
}
function faseAtual(a) {
  if (!alertaAberto(a)) return null;
  const f = FASES.find(([id]) => !faseConcluida(a, id));
  return f ? f[0] : null;
}
function segundosAte(a, iso) { return iso ? Math.round((Date.parse(iso) - Date.parse(a.primeiro)) / 1000) : null; }
function duracao(seg) {
  if (seg === null) return 'pendente';
  const m = Math.floor(seg / 60);
  return m ? `${m} min ${seg % 60} s` : `${seg} s`;
}

function atualizarStatus(a) {
  if (a.resposta.classificacao === 'fp') a.status = 'falso_positivo';
  else {
    const mapa = { contencao: 'contido', erradicacao: 'erradicado', recuperacao: 'resolvido' };
    let st = Object.keys(a.resposta.passos).length ? 'analise' : 'aberto';
    Object.entries(mapa).forEach(([fase, rot]) => { if (a.resposta.fases[fase]) st = rot; });
    a.status = st;
  }
  if (!alertaAberto(a) && !a.resposta.encerradoEm) {
    a.resposta.encerradoEm = new Date().toISOString();
    Log.registrar('ir.incident.closed', 'INFO', {
      ...ORIGEM_CONSOLE, incident_id: a.id, classification: a.status,
      time_to_contain_s: segundosAte(a, a.resposta.fases.contencao),
      time_to_resolve_s: segundosAte(a, a.resposta.encerradoEm)
    });
  }
}

function concluirPasso(a, passo, resultado) {
  a.resposta.passos[passo.id] = { em: new Date().toISOString(), resultado: resultado || null };
  Log.registrar('ir.step.completed', 'INFO', { ...ORIGEM_CONSOLE, incident_id: a.id, phase: passo.fase, step: passo.id });
  if (faseConcluida(a, passo.fase) && !a.resposta.fases[passo.fase]) {
    a.resposta.fases[passo.fase] = new Date().toISOString();
    Log.registrar('ir.phase.completed', 'INFO', { ...ORIGEM_CONSOLE, incident_id: a.id, phase: passo.fase });
  }
  atualizarStatus(a);
}

function relatorioIncidente(a) {
  const [pbId, pb] = playbookDo(a);
  const passos = FASES.slice(1).flatMap(([fase]) => passosDaFase(a, fase).map(p => {
    const feito = a.resposta.passos[p.id];
    return { fase, passo: typeof p.texto === 'function' ? p.texto(a) : p.texto, concluido_em: feito ? feito.em : null, resultado: feito ? feito.resultado : null };
  }));
  return {
    incidente: a.id, regra: a.regra, titulo: a.nome, severidade: a.severidade, dominio: a.dominio, chave: a.chave,
    playbook: `${pbId} ${pb.nome}`, status: a.status, detectado_em: a.primeiro, ocorrencias: a.ocorrencias,
    fases_concluidas: a.resposta.fases,
    metricas: { tempo_ate_contencao_s: segundosAte(a, a.resposta.fases.contencao), tempo_ate_resolucao_s: segundosAte(a, a.resposta.encerradoEm) },
    passos, evidencias_trace_id: a.evidencias
  };
}

// --- Tela do incidente
function desenharPasso(a, p, ativo) {
  const feito = a.resposta.passos[p.id];
  const texto = typeof p.texto === 'function' ? p.texto(a) : p.texto;
  const linha = el('div', { class: 'passo' + (feito ? ' feito' : '') });

  if (p.tipo === 'check') {
    const cb = el('input', { type: 'checkbox', id: `${a.id}-${p.id}` });
    cb.checked = Boolean(feito);
    cb.disabled = !ativo || Boolean(feito);
    cb.addEventListener('change', () => { concluirPasso(a, p); desenharAlertas(); });
    linha.append(el('label', { class: 'passo-check', for: cb.id }, cb, el('span', {}, texto)));
  } else if (p.tipo === 'acao') {
    const b = el('button', { type: 'button', class: 'btn-sm' + (p.perigo ? ' perigo' : '') }, feito ? 'Executado' : 'Executar');
    b.disabled = !ativo || Boolean(feito);
    b.addEventListener('click', async () => {
      b.disabled = true;
      b.textContent = 'Executando...';
      const resultado = await p.executar(a);
      concluirPasso(a, p, resultado);
      desenharAlertas();
    });
    linha.append(el('div', { class: 'passo-acao' }, el('span', {}, texto), b));
    if (feito && feito.resultado) linha.append(el('p', { class: 'passo-res' }, feito.resultado));
  } else {
    const opcoes = p.opcoes || { vp: 'Verdadeiro positivo', fp: 'Falso positivo (encerrar)' };
    linha.append(el('span', { class: 'passo-titulo' }, texto));
    if (feito) {
      linha.append(el('p', { class: 'passo-res' }, `Classificado como: ${a.resposta.classificacao === 'fp' ? opcoes.fp : opcoes.vp}.`));
    } else {
      const escolher = tipo => () => {
        a.resposta.classificacao = tipo;
        concluirPasso(a, p, tipo === 'fp' ? opcoes.fp : opcoes.vp);
        desenharAlertas();
      };
      const bVp = el('button', { type: 'button', class: 'btn-sm', onclick: escolher('vp') }, opcoes.vp);
      const bFp = el('button', { type: 'button', class: 'btn-sm ghost', onclick: escolher('fp') }, opcoes.fp);
      bVp.disabled = bFp.disabled = !ativo;
      linha.append(el('div', { class: 'decisao' }, bVp, bFp));
    }
  }
  return linha;
}

function desenharIncidente(alvo, a) {
  const [pbId, pb] = playbookDo(a);
  const atual = faseAtual(a);
  alvo.innerHTML = '';

  const copiar = el('button', { type: 'button', class: 'btn-sm ghost' }, 'Copiar relatório do incidente');
  copiar.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(JSON.stringify(relatorioIncidente(a), null, 2)); copiar.textContent = 'Relatório copiado'; }
    catch { copiar.textContent = 'Não foi possível copiar'; }
    setTimeout(() => (copiar.textContent = 'Copiar relatório do incidente'), 1800);
  });

  alvo.append(
    el('button', { type: 'button', class: 'voltar', onclick: () => { incidenteAberto = null; desenharAlertas(); } }, '← Todos os alertas'),
    el('section', { class: 'alerta inc-cabecalho sev-' + a.severidade },
      el('div', { class: 'alerta-topo' },
        el('span', { class: 'alerta-id' }, a.id),
        el('span', { class: 'sev ' + a.severidade }, SEVERIDADES[a.severidade]),
        el('span', { class: 'estado st-' + a.status }, STATUS_INCIDENTE[a.status])),
      el('h4', {}, a.nome),
      el('p', { class: 'meta' }, `${a.regra}, domínio ${a.dominio}, chave ${a.chave}`),
      el('p', { class: 'meta' }, `Playbook ${pbId}: ${pb.nome}`),
      el('div', { class: 'inc-metricas' },
        el('div', {}, el('b', {}, hora(a.primeiro)), el('span', {}, 'detectado')),
        el('div', {}, el('b', {}, duracao(segundosAte(a, a.resposta.fases.contencao))), el('span', {}, 'até a contenção')),
        el('div', {}, el('b', {}, duracao(segundosAte(a, a.resposta.encerradoEm))), el('span', {}, 'até o encerramento')))));

  FASES.forEach(([fase, nome], i) => {
    const concluida = fase === 'preparacao' || Boolean(a.resposta.fases[fase]);
    const naoSeAplica = a.status === 'falso_positivo' && !concluida;
    const estado = concluida ? 'feita' : naoSeAplica ? 'na' : fase === atual ? 'atual' : 'bloqueada';
    const rotulo = fase === 'preparacao' ? 'Pronta antes do incidente'
      : concluida ? `Concluída às ${hora(a.resposta.fases[fase])}`
      : naoSeAplica ? 'Não se aplica (falso positivo)'
      : estado === 'atual' ? 'Em andamento' : 'Aguardando a fase anterior';
    const bloco = el('section', { class: 'fase ' + estado },
      el('div', { class: 'fase-topo' },
        el('span', { class: 'fase-num' }, concluida ? '✓' : String(i + 1)),
        el('h5', {}, nome),
        el('span', { class: 'fase-estado' }, rotulo)));
    if (fase === 'preparacao') {
      const itens = [...PREPARACAO_COMUM, ...pb.preparacao];
      bloco.append(el('details', { class: 'prep' },
        el('summary', {}, `O que já estava pronto (${itens.length} itens)`),
        el('ul', {}, itens.map(t => el('li', {}, t)))));
    } else {
      passosDaFase(a, fase).forEach(p => bloco.append(desenharPasso(a, p, estado === 'atual')));
    }
    alvo.append(bloco);
  });

  const eventos = Log.itens.filter(e => a.evidencias.includes(e.trace_id));
  alvo.append(el('section', { class: 'fase feita' },
    el('div', { class: 'fase-topo' }, el('h5', {}, 'Eventos relacionados'), el('span', { class: 'fase-estado' }, plural(eventos.length, 'evento', 'eventos'))),
    eventos.length
      ? el('ol', { class: 'ev-rel' }, eventos.map(e => el('li', {},
          el('time', {}, hora(e.timestamp)), el('code', {}, e.event),
          el('span', {}, [e.reason, e.route, e.device_id, e.status && `status ${e.status}`].filter(Boolean).join(', ')))))
      : el('p', { class: 'empty' }, 'Os eventos deste alerta foram removidos do painel de logs.')),
    copiar);
}

/* =========================================================
   26. INICIALIZAÇÃO
   ========================================================= */
function relogio() {
  const d = new Date();
  document.getElementById('clock').textContent =
    String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
}

document.getElementById('copyLogs').addEventListener('click', async e => {
  const b = e.currentTarget;
  try {
    await navigator.clipboard.writeText(JSON.stringify(Log.itens, null, 2));
    b.textContent = 'Logs copiados';
  } catch {
    b.textContent = 'Não foi possível copiar';
  }
  setTimeout(() => (b.textContent = 'Copiar logs'), 1800);
});
document.getElementById('clearLogs').addEventListener('click', () => { Log.itens = []; logVazio(); agendarPainel(); });

// Abas do centro de segurança
document.querySelectorAll('[data-aba]').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('[data-aba]').forEach(x => x.setAttribute('aria-selected', String(x === b)));
  const mapa = { ataques: 'viewAtaques', logs: 'viewLogs', alertas: 'viewAlertas', painel: 'viewPainel' };
  Object.entries(mapa).forEach(([aba, id]) => { document.getElementById(id).hidden = aba !== b.dataset.aba; });
  if (b.dataset.aba === 'painel') desenharPainel();
}));
desenharAlertas();

document.querySelectorAll('[data-sim]').forEach(b => b.addEventListener('click', async () => {
  if (!sessao) return;
  b.disabled = true;
  resultadoSim('Executando...');
  try { resultadoSim(await SIMULACOES[b.dataset.sim]()); }
  finally { ativarSimulacoes(sessao ? sessao.perfil : null); }
}));
desenharArmazenamento();

(async function iniciar() {
  relogio();
  setInterval(relogio, 30000);
  logVazio();
  await iniciarChaveJWT();
  Log.registrar('app.start', 'INFO', { event_detail: 'jwt_key_generated_non_extractable' });
  telaLogin();
})();
