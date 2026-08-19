import m from 'mithril';
import CreateTokenButton from './TokensPage/CreateTokenButton';
import TokenTable from './TokensPage/TokenTable';

const TokensPage: m.Component = {
    view: () =>
        m('div', { class: 'tw:p-4' }, [
            m(
                'div',
                { class: 'tw:flex tw:justify-end tw:items-center tw:mb-6' },
                [m(CreateTokenButton)]
            ),
            m(TokenTable),
        ]),
};

export default TokensPage;
