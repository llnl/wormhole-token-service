import './styles/index.css';
import m from 'mithril';
import Hello from './views/Hello';

const root = document.getElementById('app');

if (root === null) {
    throw new Error('Unable to find the application root element.');
}

m.mount(root, Hello);
