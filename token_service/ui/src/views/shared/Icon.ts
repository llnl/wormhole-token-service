import m from 'mithril';
import {
    icon,
    type IconDefinition,
    type IconParams,
} from '@fortawesome/fontawesome-svg-core';

export interface IconAttrs {
    /** Font Awesome icon definition (e.g., faTrash, faPlus, faCheck) */
    icon: IconDefinition;
    /** Optional Tailwind or custom CSS classes */
    class?: string;
    /** Optional transform options (e.g., { rotate: 90, size: 20 }) */
    transform?: IconParams['transform'];
    /** Optional title for accessibility / tooltip */
    title?: string;
}

const Icon: m.Component<IconAttrs> = {
    view: ({ attrs }) => {
        const { icon: iconDef, class: className, transform, title } = attrs;

        const rendered = icon(iconDef, {
            classes: className ? className.split(' ') : undefined,
            transform,
            title,
        });

        if (rendered.html.length === 0) {
            return null;
        }

        // Render the SVG markup directly inside Mithril vnodes
        return m.trust(rendered.html[0]);
    },
};

export default Icon;
