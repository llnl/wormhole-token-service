import m from 'mithril';
import { DateTime } from 'luxon';
import type { Token } from '../../../models/Token';
import { TokenRepository } from '../../../repositories/TokenRepository';

const tokenRepo = new TokenRepository();

interface TokenRowAttrs {
    token: Token;
    ondelete: (token: Token) => void;
}

const renderTimestampCell = (seconds: number | null): m.Children => {
    if (seconds === null) {
        return m('td', { class: 'tw:whitespace-nowrap' }, 'N/A');
    }
    const dt = DateTime.fromSeconds(seconds);
    const fullTimestamp = dt.toISO();
    return m(
        'td',
        {
            class: 'tw:whitespace-nowrap',
            ...(fullTimestamp ? { title: fullTimestamp } : {}),
        },
        dt.toISODate() ?? 'N/A'
    );
};

const TokenRow: m.Component<TokenRowAttrs> = {
    view: ({ attrs }) =>
        m('tr', [
            m('td', attrs.token.name),
            renderTimestampCell(attrs.token.iat),
            renderTimestampCell(attrs.token.nbf),
            renderTimestampCell(attrs.token.exp),
            m('td', [
                m(
                    'button',
                    {
                        class: 'tw:d-btn tw:d-btn-error tw:d-btn-sm',
                        onclick: async () => {
                            await tokenRepo.deleteToken(attrs.token);
                            attrs.ondelete(attrs.token);
                        },
                    },
                    'Delete'
                ),
            ]),
        ]),
};

export default TokenRow;
