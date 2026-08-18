import './styles/index.css';
import m from 'mithril';
import TokensPage from './views/pages/TokensPage';
import Root from './views/Root';

const root = document.getElementById('app');

if (root === null) {
    throw new Error('Unable to find the application root element.');
}

m.mount(root, {
    view: () => m(Root, m(TokensPage)),
});
