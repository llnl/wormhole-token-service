import m from 'mithril';
import { faGithub } from '@fortawesome/free-brands-svg-icons';
import Icon from './shared/Icon';

const REPO_URL = 'https://github.com/LLNL/wormhole-token-service';
const COPYRIGHT = 'Copyright 2026, Lawrence Livermore National Security, LLC';

const Footer: m.Component = {
    view: () =>
        m(
            'footer',
            {
                class: 'tw:d-footer tw:d-footer-center tw:bg-base-100 tw:text-base-content tw:p-4 tw:shadow-sm',
            },
            m(
                'div',
                { class: 'tw:flex tw:flex-col tw:items-center tw:gap-1' },
                [
                    m(
                        'a',
                        {
                            href: REPO_URL,
                            target: '_blank',
                            rel: 'noopener noreferrer',
                            'aria-label': 'GitHub repository',
                            class: 'tw:d-link tw:d-link-hover tw:text-2xl',
                        },
                        m(Icon, { icon: faGithub, title: 'GitHub repository' })
                    ),
                    m('p', { class: 'tw:text-sm' }, COPYRIGHT),
                ]
            )
        ),
};

export default Footer;
