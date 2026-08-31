import m from 'mithril';

interface ApiError {
    response?: {
        detail?: string | ({ msg?: string } | string)[];
        message?: string;
    };
    message?: string;
}

export abstract class AbstractRepository {
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    protected constructor() {}

    private normalizeError(error: unknown): Error {
        const err = error as ApiError | undefined;
        const detail = err?.response?.detail;

        if (typeof detail === 'string') {
            return new Error(detail);
        }
        if (Array.isArray(detail)) {
            const messages = detail
                .map((d) =>
                    typeof d === 'string' ? d : (d.msg ?? JSON.stringify(d))
                )
                .filter((msg) => msg.length > 0);
            return new Error(
                messages.length > 0
                    ? messages.join(', ')
                    : 'An unexpected error occurred.'
            );
        }
        if (err?.response?.message) {
            return new Error(err.response.message);
        }
        if (err?.message && err.message !== '[object Object]') {
            return new Error(err.message);
        }
        return new Error('An unexpected error occurred.');
    }

    protected async get<T>(
        route: string,
        params?: Record<string, unknown>
    ): Promise<T> {
        try {
            return await m.request<T>(route, {
                method: 'GET',
                params: params,
            });
        } catch (error: unknown) {
            throw this.normalizeError(error);
        }
    }

    protected async post<T>(
        route: string,
        data: Record<string, string>
    ): Promise<T> {
        try {
            return await m.request<T>(route, {
                method: 'POST',
                body: new URLSearchParams(data).toString(),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                serialize: (body: string): string => body,
            });
        } catch (error: unknown) {
            throw this.normalizeError(error);
        }
    }

    protected async delete(
        route: string,
        params?: Record<string, unknown>
    ): Promise<void> {
        try {
            await m.request<unknown>(route, {
                method: 'DELETE',
                params: params,
            });
        } catch (error: unknown) {
            throw this.normalizeError(error);
        }
    }
}
