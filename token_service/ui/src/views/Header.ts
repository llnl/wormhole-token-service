import m from 'mithril';

const Header: m.Component = {
    view: () =>
        m(
            'div',
            {
                class: 'tw:sticky tw:top-0 tw:z-50 tw:d-navbar tw:bg-base-100 tw:shadow-sm',
            },
            [
                m(
                    'a',
                    { class: 'tw:d-btn tw:d-btn-ghost tw:text-xl' },
                    'Wormhole Token Service'
                ),
            ]
        ),
};

export default Header;
