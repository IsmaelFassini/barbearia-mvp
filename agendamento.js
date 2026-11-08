
function validarAgendamento(telefone, senha) {
    if (!telefone || telefone.length < 10) return false;
    if (!senha || senha.length < 6) return false;
    return true;
}
module.exports = { validarAgendamento };