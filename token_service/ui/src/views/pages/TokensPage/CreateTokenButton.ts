import m from 'mithril';

const CreateTokenButton: m.Component = {
    view: () =>
        m('button', { class: 'tw:d-btn tw:d-btn-primary' }, 'Create Token'),
};

export default CreateTokenButton;
