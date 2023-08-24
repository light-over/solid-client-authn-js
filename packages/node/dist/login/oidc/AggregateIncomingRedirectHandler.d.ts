/// <reference types="node" />
import type { IIncomingRedirectHandler, ISessionInfo } from "@inrupt/solid-client-authn-core";
import { AggregateHandler } from "@inrupt/solid-client-authn-core";
import type { EventEmitter } from "events";
export default class AggregateIncomingRedirectHandler extends AggregateHandler<[
    string,
    EventEmitter
], ISessionInfo & {
    fetch: typeof fetch;
}> implements IIncomingRedirectHandler {
    constructor(redirectHandlers: IIncomingRedirectHandler[]);
}
