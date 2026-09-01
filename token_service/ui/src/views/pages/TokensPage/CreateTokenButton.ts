import m from 'mithril';
import { DateTime } from 'luxon';
import { Token } from '../../../models/Token';
import { TokenRepository } from '../../../repositories/TokenRepository';

const tokenRepo = new TokenRepository();

interface CreateTokenButtonAttrs {
    oncreated: (createdToken: string) => void;
}

interface CreateTokenButtonState {
    isOpen: boolean;
    name: string;
    nbf: string;
    exp: string;
    isSubmitting: boolean;
    error: string | null;
}

const close = (state: CreateTokenButtonState): void => {
    state.isOpen = false;
};

const open = (state: CreateTokenButtonState): void => {
    state.isOpen = true;
    state.name = '';
    state.nbf = '';
    state.exp = '';
    state.error = null;
};

const unixSeconds = (value: string): number | null =>
    value ? DateTime.fromISO(value).toSeconds() : null;

const CreateTokenButton: m.Component<
    CreateTokenButtonAttrs,
    CreateTokenButtonState
> = {
    oninit: ({ state }) => {
        state.isOpen = false;
        state.name = '';
        state.nbf = '';
        state.exp = '';
        state.isSubmitting = false;
        state.error = null;
    },
    view: ({ attrs, state }) => [
        m(
            'button',
            {
                class: 'tw:d-btn tw:d-btn-primary',
                onclick: () => {
                    open(state);
                },
            },
            'Create Token'
        ),
        state.isOpen &&
            m('div', { class: 'tw:d-modal tw:d-modal-open' }, [
                m('div', { class: 'tw:d-modal-box' }, [
                    m(
                        'h3',
                        { class: 'tw:text-lg tw:font-bold tw:mb-4' },
                        'Create Token'
                    ),
                    m(
                        'form',
                        {
                            class: 'tw:flex tw:flex-col tw:gap-4',
                            onsubmit: async (event: SubmitEvent) => {
                                event.preventDefault();
                                const name = state.name.trim();
                                if (!name) {
                                    state.error = 'Name is required.';
                                    return;
                                }

                                state.isSubmitting = true;
                                state.error = null;

                                try {
                                    const token = new Token({
                                        name,
                                        nbf: unixSeconds(state.nbf),
                                        exp: unixSeconds(state.exp),
                                    });
                                    const createdToken =
                                        await tokenRepo.createToken(token);
                                    close(state);
                                    attrs.oncreated(createdToken);
                                } catch (error: unknown) {
                                    state.error =
                                        error instanceof Error
                                            ? error.message
                                            : 'Unable to create token.';
                                } finally {
                                    state.isSubmitting = false;
                                }
                            },
                        },
                        [
                            m('div', { class: 'tw:d-form-control tw:w-full' }, [
                                m('label', { class: 'tw:d-label' }, [
                                    m(
                                        'span',
                                        {
                                            class: 'tw:d-label-text tw:font-medium',
                                        },
                                        'Name'
                                    ),
                                ]),
                                m('input', {
                                    class: 'tw:d-input tw:d-input-bordered tw:w-full',
                                    type: 'text',
                                    placeholder: 'Token name',
                                    required: true,
                                    value: state.name,
                                    oninput: (event: InputEvent) => {
                                        state.name = (
                                            event.currentTarget as HTMLInputElement
                                        ).value;
                                    },
                                }),
                            ]),
                            m('div', { class: 'tw:d-form-control tw:w-full' }, [
                                m('label', { class: 'tw:d-label' }, [
                                    m(
                                        'span',
                                        {
                                            class: 'tw:d-label-text tw:font-medium',
                                        },
                                        'Not Before'
                                    ),
                                ]),
                                m('input', {
                                    class: 'tw:d-input tw:d-input-bordered tw:w-full',
                                    type: 'date',
                                    value: state.nbf,
                                    oninput: (event: InputEvent) => {
                                        state.nbf = (
                                            event.currentTarget as HTMLInputElement
                                        ).value;
                                    },
                                }),
                            ]),
                            m('div', { class: 'tw:d-form-control tw:w-full' }, [
                                m('label', { class: 'tw:d-label' }, [
                                    m(
                                        'span',
                                        {
                                            class: 'tw:d-label-text tw:font-medium',
                                        },
                                        'Expiration'
                                    ),
                                ]),
                                m('input', {
                                    class: 'tw:d-input tw:d-input-bordered tw:w-full',
                                    type: 'date',
                                    value: state.exp,
                                    oninput: (event: InputEvent) => {
                                        state.exp = (
                                            event.currentTarget as HTMLInputElement
                                        ).value;
                                    },
                                }),
                            ]),
                            state.error &&
                                m(
                                    'div',
                                    {
                                        class: 'tw:d-alert tw:d-alert-error tw:text-sm',
                                    },
                                    state.error
                                ),
                            m('div', { class: 'tw:d-modal-action tw:mt-2' }, [
                                m(
                                    'button',
                                    {
                                        class: 'tw:d-btn',
                                        type: 'button',
                                        disabled: state.isSubmitting,
                                        onclick: () => {
                                            close(state);
                                        },
                                    },
                                    'Cancel'
                                ),
                                m(
                                    'button',
                                    {
                                        class: 'tw:d-btn tw:d-btn-primary',
                                        type: 'submit',
                                        disabled:
                                            state.isSubmitting ||
                                            !state.name.trim(),
                                    },
                                    state.isSubmitting
                                        ? 'Creating...'
                                        : 'Create'
                                ),
                            ]),
                        ]
                    ),
                ]),
                m('button', {
                    class: 'tw:d-modal-backdrop',
                    onclick: () => {
                        close(state);
                    },
                }),
            ]),
    ],
};

export default CreateTokenButton;
