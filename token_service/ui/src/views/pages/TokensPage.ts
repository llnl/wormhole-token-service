import m from 'mithril';
import CreateTokenButton from './TokensPage/CreateTokenButton';
import CreatedTokenAlert from './TokensPage/CreatedTokenAlert';
import TokenTable from './TokensPage/TokenTable';

interface TokensPageState {
    tokenTableKey: number;
    createdToken: string | null;
}

const TokensPage: m.Component<Record<string, never>, TokensPageState> = {
    oninit: ({ state }) => {
        state.tokenTableKey = 0;
        state.createdToken = null;
    },
    view: ({ state }) => {
        const children: m.Children = [
            m(
                'div',
                {
                    key: 'create-token',
                    class: 'tw:flex tw:justify-end tw:items-center tw:mb-6',
                },
                [
                    m(CreateTokenButton, {
                        oncreated: (createdToken: string) => {
                            state.createdToken = createdToken;
                            state.tokenTableKey += 1;
                        },
                    }),
                ]
            ),
        ];

        if (state.createdToken) {
            children.push(
                m(CreatedTokenAlert, {
                    key: 'created-token-alert',
                    token: state.createdToken,
                    ondismiss: () => {
                        state.createdToken = null;
                    },
                })
            );
        }

        children.push(
            m(
                'div',
                { key: `token-table-${String(state.tokenTableKey)}` },
                m(TokenTable)
            )
        );

        return m('div', { class: 'tw:p-4' }, children);
    },
};

export default TokensPage;
