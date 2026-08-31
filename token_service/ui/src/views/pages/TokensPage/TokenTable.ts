import m from 'mithril';
import { TokenRepository } from '../../../repositories/TokenRepository';
import type { Token } from '../../../models/Token';
import TokenRow from './TokenRow';

const tokenRepo: TokenRepository = new TokenRepository();

interface TokenTableState {
    tokens: Token[];
}

const TokenTable: m.Component<Record<string, never>, TokenTableState> = {
    oninit: ({ state }) => {
        state.tokens = [];
        void tokenRepo.getAllTokens().then((tokens) => {
            state.tokens = tokens;
        });
    },
    view: ({ state }) => {
        const tokens: Token[] = state.tokens;
        return m('div', { class: 'tw:overflow-x-auto' }, [
            m('table', { class: 'tw:d-table tw:w-full tw:border' }, [
                m('thead', [
                    m('tr', [
                        m('th', { class: 'tw:w-full' }, 'Name'),
                        m('th', { class: 'tw:whitespace-nowrap' }, 'Issued At'),
                        m(
                            'th',
                            { class: 'tw:whitespace-nowrap' },
                            'Not Before'
                        ),
                        m(
                            'th',
                            { class: 'tw:whitespace-nowrap' },
                            'Expiration'
                        ),
                        m('th'),
                    ]),
                ]),
                m('tbody', [
                    tokens.length > 0
                        ? tokens.map((token: Token) =>
                              m(TokenRow, {
                                  key: token.id ?? token.name,
                                  token,
                                  ondelete: (deletedToken: Token) => {
                                      state.tokens = state.tokens.filter(
                                          (existingToken) =>
                                              existingToken.name !==
                                              deletedToken.name
                                      );
                                  },
                              })
                          )
                        : m('tr', [
                              m(
                                  'td',
                                  {
                                      colspan: 5,
                                      class: 'tw:text-center tw:py-8 tw:text-base-content/50',
                                  },
                                  'No tokens to display'
                              ),
                          ]),
                ]),
            ]),
        ]);
    },
};

export default TokenTable;
