import m from 'mithril';

const Hello = {
  view: () => m('div', { class: 'p-6' }, [
    m('h1', { class: 'app-title' }, 'Hello, Token Service!'),
    m('p', { class: 'mt-2 text-gray-600' }, 'Mithril and Tailwind are working.'),
  ])
};

export default Hello;

