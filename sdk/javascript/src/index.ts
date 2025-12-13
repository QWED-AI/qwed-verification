import axios, { AxiosInstance } from 'axios';

export interface VerificationResponse {
    status: string;
    final_answer?: any;
    user_query?: string;
    translation?: Record<string, any>;
    verification?: Record<string, any>;
    latency_ms?: number;
    error?: string;
}

export interface LogicResponse {
    status: string;
    model?: Record<string, any>;
    error?: string;
}

export interface FactResponse {
    verdict: string;
    reasoning?: string;
    citations?: string[];
}

export class QwedClient {
    private client: AxiosInstance;

    constructor(apiKey: string, baseURL: string = "https://api.qwed.tech/v1") {
        this.client = axios.create({
            baseURL,
            headers: {
                'X-API-Key': apiKey,
                'Content-Type': 'application/json'
            }
        });
    }

    /**
     * Verify a natural language math or general query.
     */
    async verifyNaturalLanguage(query: string, provider?: string): Promise<VerificationResponse> {
        const payload: any = { query };
        if (provider) payload.provider = provider;

        const response = await this.client.post<VerificationResponse>('/verify/natural_language', payload);
        return response.data;
    }

    /**
     * Verify a logic puzzle.
     */
    async verifyLogic(query: string, provider?: string): Promise<LogicResponse> {
        const payload: any = { query };
        if (provider) payload.provider = provider;

        const response = await this.client.post<LogicResponse>('/verify/logic', payload);
        return response.data;
    }

    /**
     * Verify a fact against a context.
     */
    async verifyFact(claim: string, context: string, provider?: string): Promise<FactResponse> {
        const payload: any = { claim, context };
        if (provider) payload.provider = provider;

        const response = await this.client.post<FactResponse>('/verify/fact', payload);
        return response.data;
    }
}
