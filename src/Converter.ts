/**
 *
 * @param thing
 */
export const toString = (thing: Buffer|string) => {
    if (typeof thing === 'string') {
        return thing;
    }
    return Buffer.from(thing).toString('binary');
};

/**
 *
 * @param thing
 */
export const toBuffer = (thing: any) => {
    if (thing === undefined) {
        return undefined;
    }

    if (thing === Object(thing)) {
        if (thing instanceof ArrayBuffer) {
            return thing;
        }
    }

    if (typeof thing !== 'string') {
        throw new Error('Tried to convert a non-string of type '
            + typeof thing
            + ' to an array buffer');
    }
    return Buffer.from(thing);
};

/**
 *
 * @param thing
 */
export const objToBuffer = (thing: any) => {
    const myBuffer = new ArrayBuffer(thing.length);
    const res = new Uint8Array(myBuffer);
    for (let i = 0; i < thing.length; ++i) {
        res[i] = thing[i];
    }
    return res;
};
