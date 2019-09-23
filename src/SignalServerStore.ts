/**
 * The user's generated pre-key bundle.
 */
export interface PreKeyBundle {
    identityKey: Buffer;
    registrationId: number;
    preKey: {
        keyId: number;
        publicKey: Buffer;
    };
    signedPreKey: {
        keyId: number;
        publicKey: Buffer;
        signature: Buffer;
    };
}

export interface ServerConfig {
    apiURL: string;
    apiKey: string;
    login: {
        username: string;
        password: string;
    };
}

export interface SignalServerStore {
    config: ServerConfig;
    /**
     * When a user logs on they should generate their
     * keys and then register them with the server.
     * @param userId The user ID.
     * @param preKeyBundle The user's generated pre-key bundle.
     */
    registerNewPreKeyBundle(userId: string, preKeyBundle: PreKeyBundle): Promise<boolean>;
    /**
     * Check if a user id exists
     * @param userId The ID of the user.
     */
    userIsExistant(userId: string): Promise<boolean>;
    /**
     * Gets the pre-key bundle for the given user ID.
     * If you want to start a conversation with a user,
     * you need to fetch their pre-key bundle first.
     * @param userId The ID of the user.
     */
    getPreKeyBundle(userId: string): Promise<PreKeyBundle | undefined>;
}
