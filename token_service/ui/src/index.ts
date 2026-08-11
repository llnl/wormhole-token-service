import './styles/index.css';
import m from 'mithril';
import Hello from './views/Hello';

const root = document.getElementById('app')!;

m.mount(root, Hello);
