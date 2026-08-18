import m from 'mithril';
import Header from './Header';

const Root: m.Component = {
    view: (vnode: m.Vnode) =>
        m('div', { class: 'tw:min-h-screen tw:flex tw:flex-col' }, [
            m(Header),
            m('main', { class: 'tw:p-2 tw:flex-grow' }, vnode.children),
        ]),
};

export default Root;
