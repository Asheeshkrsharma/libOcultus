"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toString = (thing) => {
    if (typeof thing === 'string') {
        return thing;
    }
    return Buffer.from(thing).toString('binary');
};
exports.toBuffer = (thing) => {
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
exports.objToBuffer = (thing) => {
    const myBuffer = new ArrayBuffer(thing.length);
    const res = new Uint8Array(myBuffer);
    for (let i = 0; i < thing.length; ++i) {
        res[i] = thing[i];
    }
    return res;
};
//# sourceMappingURL=Converter.js.map