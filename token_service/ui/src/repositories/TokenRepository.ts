import { AbstractRepository } from './AbstractRepository';
import { Token } from '../models/Token';

export class TokenRepository extends AbstractRepository {
    public constructor() {
        super();
    }

    public getAllTokens(): Token[] {
        return [
            new Token({ name: 'Token 1', exp: 1735689600 }),
            new Token({ name: 'Token 2', exp: 1751328000 }),
            new Token({ name: 'Token 3', exp: 1767225600 }),
        ];
    }
}
