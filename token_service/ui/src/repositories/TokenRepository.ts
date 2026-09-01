import { AbstractRepository } from './AbstractRepository';
import { Token } from '../models/Token';

export class TokenRepository extends AbstractRepository {
    public constructor() {
        super();
    }

    public async getAllTokens(): Promise<Token[]> {
        const tokens = await this.get<Partial<Token>[]>('/api/v1/token');

        return tokens.map((token) => new Token(token));
    }

    public async createToken(token: Token): Promise<string> {
        const data: Record<string, string> = { name: token.name };

        if (token.nbf !== null) {
            data.nbf = token.nbf.toString();
        }
        if (token.exp !== null) {
            data.exp = token.exp.toString();
        }

        return await this.post<string>('/api/v1/token', data);
    }

    public async deleteToken(token: Token): Promise<void> {
        await this.delete('/api/v1/token', { name: token.name });
    }
}
