import m from 'mithril';

const Hello = {
    view: () =>
        m('div', { class: 'tw:p-6' }, [
            m('h1', { class: 'app-title' }, 'Hello, Token Service!'),
            m(
                'p',
                { class: 'tw:mt-2 tw:text-gray-600' },
                'Mithril and Tailwind are working.'
            ),
            m('button', { class: 'tw:d-btn' }, 'This is a DaisyUI button'),
        ]),
};

export default Hello;
