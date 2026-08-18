import m from 'mithril';
import { DateTime } from 'luxon';
import { TokenRepository } from '../../../repositories/TokenRepository';
import type { Token } from '../../../models/Token';

const tokenRepo: TokenRepository = new TokenRepository();

const TokenTable: m.Component = {
    view: () => {
        const tokens: Token[] = tokenRepo.getAllTokens();
        return m('div', { class: 'tw:overflow-x-auto' }, [
            m('table', { class: 'tw:d-table tw:w-full tw:border' }, [
                m('thead', [
                    m('tr', [
                        m('th', { class: 'tw:w-full' }, 'Name'),
                        m(
                            'th',
                            { class: 'tw:whitespace-nowrap' },
                            'Expiration'
                        ),
                        m('th', ''), // Unlabeled action column
                    ]),
                ]),
                m('tbody', [
                    tokens.length > 0
                        ? tokens.map((token: Token) =>
                              m('tr', [
                                  m('td', token.name),
                                  m(
                                      'td',
                                      { class: 'tw:whitespace-nowrap' },
                                      token.exp
                                          ? DateTime.fromSeconds(
                                                token.exp
                                            ).toISODate()
                                          : 'N/A'
                                  ),
                                  m('td', [
                                      m(
                                          'button',
                                          {
                                              class: 'tw:d-btn tw:d-btn-error tw:d-btn-sm',
                                          },
                                          'Delete'
                                      ),
                                  ]),
                              ])
                          )
                        : m('tr', [
                              m(
                                  'td',
                                  {
                                      colspan: 3,
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
