
const { validarAgendamento } = require('./agendamento');

describe('Suíte de Testes - MVP Barbearia', () => {
    test('RF02: Deve aprovar um agendamento com dados válidos', () => {
        const resultado = validarAgendamento('51987654321', 'senha123');
        expect(resultado).toBe(true);
    });

    test('RNF02: Deve rejeitar agendamento com telefone incompleto ou vazio', () => {
        const resultado = validarAgendamento('5198', 'senha123');
        expect(resultado).toBe(false);
    });
});