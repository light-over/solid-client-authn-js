import type { JWK } from "jose";
import type { IClient, IIssuerConfig, KeyPair } from "@inrupt/solid-client-authn-core";
import type { TokenEndpointInput } from "../dpop/tokenExchange";
export declare const mockJwk: () => JWK;
export declare const mockKeyPair: () => Promise<KeyPair>;
export declare const mockIssuer: () => IIssuerConfig;
export declare const mockWebId: () => string;
export declare const mockEndpointInput: () => TokenEndpointInput;
export declare function generateMockJwt(): Promise<void>;
export declare const mockIdToken: () => string;
export type AccessJwt = {
    sub: string;
    iss: string;
    aud: string;
    nbf: number;
    exp: number;
    cnf: {
        jkt: string;
    };
};
export declare const mockKeyBoundToken: () => AccessJwt;
export declare const mockBearerAccessToken: () => string;
export type TokenEndpointRawResponse = {
    access_token: string;
    id_token: string;
    refresh_token?: string;
    token_type: string;
};
export declare const mockBearerTokens: () => TokenEndpointRawResponse;
export declare const mockDpopTokens: () => TokenEndpointRawResponse;
export declare const mockClient: (clientId?: string) => IClient;
export declare const mockFetch: (payload: string, statusCode: number) => import("jest-mock").MockInstance<typeof fetch> & {} & typeof fetch;
