// Sessão no app: versão inicial (antes do hardening da Sprint 3).
function salvarSessao(token, usuario) {
  localStorage.setItem('token', token);
  document.getElementById('saudacao').innerHTML = 'Olá, ' + usuario.nome;
}

function filtrarVeiculos(lista, expressao) {
  return lista.filter(v => eval(expressao));
}
