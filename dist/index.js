var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};

// src/index.ts
var src_exports = {};
__export(src_exports, {
  decryptPDF: () => decryptPDF
});
module.exports = __toCommonJS(src_exports);

// src/pdf-lib_patch.ts
var import_pdf_lib2 = require("pdf-lib");
var import_pdf_lib3 = require("pdf-lib");
var import_pdf_lib4 = require("pdf-lib");

// src/PDFSecurity.ts
var CryptoJS = __toESM(require("crypto-js"));
var import_pdf_lib = require("pdf-lib");

// src/utils.ts
var buffer2Str = (b, pos, len) => {
  const _str = [];
  const _pos = pos || 0;
  const _len = len || b.length;
  for (let i = 0; i < _len; i++) {
    if (typeof b[_pos + i] === "number") {
      _str.push(String.fromCodePoint(b[_pos + i]));
    }
  }
  return _str.join("");
};
var buffer2Hex = (b, pos, len) => {
  const _str = [];
  const _pos = pos || 0;
  const _len = len || b.length;
  for (let i = 0; i < _len; i++) {
    if (typeof b[_pos + i] === "number") {
      _str.push(b[_pos + i].toString(16).padStart(2, "0"));
    }
  }
  return _str.join("");
};

// src/PDFSecurity.ts
var PDFSecurity = class _PDFSecurity {
  /*   
    ID file is an array of two byte-string constituing 
    a file identifier
  
    Required if Encrypt entry is present in Trailer
    Doesn't really matter what it is as long as it is 
    consistently used. 
    */
  static generateFileID(info) {
    return wordArrayToBuffer(CryptoJS.MD5(info.toString()));
  }
  static generateRandomWordArray(bytes) {
    return CryptoJS.lib.WordArray.random(bytes);
  }
  static create(document, options = {}) {
    return new _PDFSecurity(document, options);
  }
  static decrypter(encryptionDic, context, password, reqPermission) {
    const filter = encryptionDic.get(import_pdf_lib.PDFName.of("Filter"));
    if (!(filter instanceof import_pdf_lib.PDFName) || filter.toString() !== "/Standard") {
      throw new Error(`Unsupport security handler. ${filter == null ? void 0 : filter.toString()}`);
    }
    const keylength = encryptionDic.get(import_pdf_lib.PDFName.of("Length"));
    if (!(keylength instanceof import_pdf_lib.PDFNumber)) {
      throw new Error(`Unsupport Key length`);
    }
    const version = encryptionDic.get(import_pdf_lib.PDFName.of("V"));
    if (!(version instanceof import_pdf_lib.PDFNumber) || version.asNumber() <= 0 || version.asNumber() === 3 || version.asNumber() > 6) {
      throw new Error(`Unsupport encrypt version.`);
    }
    const permission = encryptionDic.get(import_pdf_lib.PDFName.of("P"));
    if (!(permission instanceof import_pdf_lib.PDFNumber)) {
      throw new Error(`Permision noentry.`);
    }
    const revision = encryptionDic.get(import_pdf_lib.PDFName.of("R"));
    if (!(revision instanceof import_pdf_lib.PDFNumber) || revision.asNumber() < 2 || revision.asNumber() > 6) {
      throw new Error(`Unsupport revesion.`);
    }
    if (!(context.trailerInfo.ID instanceof import_pdf_lib.PDFArray) || !context.trailerInfo.ID.asArray()[0]) {
      throw new Error(`DocumentID undefined.`);
    }
    const documentID = context.trailerInfo.ID.asArray()[0];
    if (!(documentID instanceof import_pdf_lib.PDFHexString)) {
      throw new Error(`DocumentID undefined.`);
    }
    const ownerPasswordValue = encryptionDic.get(import_pdf_lib.PDFName.of("O"));
    if (!(ownerPasswordValue instanceof import_pdf_lib.PDFHexString) && !(ownerPasswordValue instanceof import_pdf_lib.PDFString)) {
      throw new Error("O notentry");
    }
    const ownerKey = encryptionDic.get(import_pdf_lib.PDFName.of("OE"));
    if (version.asNumber() === 5 && !(ownerKey instanceof import_pdf_lib.PDFHexString) && !(ownerKey instanceof import_pdf_lib.PDFString)) {
      throw new Error("OE notentry");
    }
    const userPasswordValue = encryptionDic.get(import_pdf_lib.PDFName.of("U"));
    if (!(userPasswordValue instanceof import_pdf_lib.PDFHexString) && !(userPasswordValue instanceof import_pdf_lib.PDFString)) {
      throw new Error("U notentry");
    }
    const userKey = encryptionDic.get(import_pdf_lib.PDFName.of("UE"));
    if (version.asNumber() === 5 && !(userKey instanceof import_pdf_lib.PDFHexString) && !(userKey instanceof import_pdf_lib.PDFString)) {
      throw new Error("OE notentry");
    }
    const perms = encryptionDic.get(import_pdf_lib.PDFName.of("Perms"));
    if (version.asNumber() === 5 && !(perms instanceof import_pdf_lib.PDFHexString) && !(perms instanceof import_pdf_lib.PDFString)) {
      throw new Error("OE notentry");
    }
    const encryptMetadataEntry = encryptionDic.get(import_pdf_lib.PDFName.of("EncryptMetadata"));
    const encryptMetadata = encryptMetadataEntry instanceof import_pdf_lib.PDFBool ? encryptMetadataEntry.asBoolean() : true;
    let passwordCheck = "N";
    const ownerPasswordKey = checkOwnerpassword({
      version: version.asNumber(),
      documentID: documentID.asBytes(),
      encryptMetadata,
      securityRevision: revision.asNumber(),
      keyLength: keylength.asNumber(),
      permissionNo: permission.asNumber(),
      ownerPassword: password || "",
      O: ownerPasswordValue.asBytes(),
      U: userPasswordValue.asBytes(),
      OE: ownerKey == null ? void 0 : ownerKey.asBytes(),
      Perms: perms == null ? void 0 : perms.asBytes(),
      P: permission.asNumber()
    });
    if (ownerPasswordKey) {
      passwordCheck = "O";
    }
    const userPasswordKey = checkUserpassword({
      version: version.asNumber(),
      documentID: documentID.asBytes(),
      encryptMetadata,
      securityRevision: revision.asNumber(),
      keyLength: keylength.asNumber(),
      permissionNo: permission.asNumber(),
      userPassword: password || "",
      O: ownerPasswordValue.asBytes(),
      U: userPasswordValue.asBytes(),
      UE: userKey == null ? void 0 : userKey.asBytes(),
      Perms: perms == null ? void 0 : perms.asBytes(),
      P: permission.asNumber()
    });
    if (passwordCheck !== "O" && userPasswordKey) {
      passwordCheck = "U";
    }
    if (ownerPasswordKey && passwordCheck === "O") {
      return {
        decrypt: getDecryptFn(version.asNumber(), ownerPasswordKey, keylength.asNumber()),
        reEncrypt: (obj, gen) => {
          return _getEncryptFn(obj, gen, version.asNumber(), keylength.asNumber(), ownerPasswordKey);
        }
      };
    } else if (userPasswordKey && passwordCheck === "U") {
      if (passwordCheck === "U") {
        if (reqPermission) {
          const permissionNum = permission.asNumber();
          let reject = false;
          if (reqPermission.printing) {
            if (revision.asNumber() <= 2) {
              if (!(permissionNum & 4)) {
                reject = true;
              }
            } else {
              if (reqPermission.printing === "lowResolution" && !(permissionNum & 4)) {
                reject = true;
              }
              if (reqPermission.printing === "highResolution" && !(permissionNum & 2052)) {
                reject = true;
              }
            }
          }
          if (reqPermission.modifying && !(permissionNum & 8)) {
            reject = true;
          }
          if (reqPermission.copying && !(permissionNum & 16)) {
            reject = true;
          }
          if (reqPermission.annotating && !(permissionNum & 32)) {
            reject = true;
          }
          if (reqPermission.fillingForms && !(permissionNum & 64)) {
            reject = true;
          }
          if (reqPermission.contentAccessibility && !(permissionNum & 128)) {
            reject = true;
          }
          if (reqPermission.documentAssembly && !(permissionNum & 256)) {
            reject = true;
          }
          if (!reject) {
            return {
              decrypt: getDecryptFn(version.asNumber(), userPasswordKey, keylength.asNumber()),
              reEncrypt: (obj, gen) => {
                return _getEncryptFn(obj, gen, version.asNumber(), keylength.asNumber(), userPasswordKey);
              }
            };
          }
        }
      }
    }
    throw new Error(`Document restriction permission denied.`);
  }
  constructor(document, options = {}) {
    if (!options.ownerPassword && !options.userPassword) {
      throw new Error("None of owner password and user password is defined.");
    }
    this.document = document;
    this._setupEncryption(options);
  }
  /* 
  Handle all encryption process and give back 
  EncryptionDictionary that is required
  to be plugged into Trailer of the PDF 
  */
  _setupEncryption(options) {
    switch (options.pdfVersion) {
      case "1.4":
      case "1.5":
        this.version = 2;
        break;
      case "1.6":
      case "1.7":
        this.version = 4;
        break;
      case "1.7ext3":
        this.version = 5;
        break;
      case "2.0":
        this.version = 5;
        this.revesion = 6;
        break;
      default:
        this.version = 1;
        break;
    }
    switch (this.version) {
      case 1:
      case 2:
      case 4:
        this.dictionary = this._setupEncryptionV1V2V4(this.version, options);
        break;
    }
  }
  _setupEncryptionV1V2V4(v, options) {
    const encDict = {
      Filter: "Standard"
    };
    let r;
    let permissions;
    switch (v) {
      case 1:
        r = 2;
        this.keyBits = 40;
        permissions = getPermissionsR2(options.permissions);
        break;
      case 2:
        r = 3;
        this.keyBits = 128;
        permissions = getPermissionsR3(options.permissions);
        break;
      case 4:
        r = 4;
        this.keyBits = 128;
        permissions = getPermissionsR3(options.permissions);
        break;
      default:
        throw new Error("Unknown v value");
    }
    const paddedUserPassword = processPasswordR2R3R4(
      options.userPassword
    );
    const paddedOwnerPassword = options.ownerPassword ? processPasswordR2R3R4(options.ownerPassword) : paddedUserPassword;
    const ownerPasswordEntry = getOwnerPasswordR2R3R4(
      r,
      this.keyBits,
      paddedUserPassword,
      paddedOwnerPassword
    );
    this.encryptionKey = getEncryptionKeyR2R3R4(
      r,
      this.keyBits,
      this.document._id,
      paddedUserPassword,
      ownerPasswordEntry,
      permissions
    );
    let userPasswordEntry;
    if (r === 2) {
      userPasswordEntry = getUserPasswordR2(this.encryptionKey);
    } else {
      userPasswordEntry = getUserPasswordR3R4(
        this.document._id,
        this.encryptionKey
      );
    }
    encDict.V = v;
    if (v >= 2) {
      encDict.Length = this.keyBits;
    }
    if (v === 4) {
      encDict.CF = {
        StdCF: {
          AuthEvent: "DocOpen",
          CFM: "AESV2",
          Length: this.keyBits / 8
        }
      };
      encDict.StmF = "StdCF";
      encDict.StrF = "StdCF";
    }
    encDict.R = r;
    encDict.O = import_pdf_lib.PDFHexString.of(buffer2Hex(wordArrayToBuffer(ownerPasswordEntry)));
    encDict.U = import_pdf_lib.PDFHexString.of(buffer2Hex(wordArrayToBuffer(userPasswordEntry)));
    encDict.P = permissions;
    return encDict;
  }
  getEncryptFn(obj, gen) {
    return _getEncryptFn(obj, gen, this.version, this.keyBits, this.encryptionKey);
  }
};
var getPermissionsR2 = (permissionObject = {}) => {
  let permissions = 4294967232 >> 0;
  if (permissionObject.printing) {
    permissions |= 4;
  }
  if (permissionObject.modifying) {
    permissions |= 8;
  }
  if (permissionObject.copying) {
    permissions |= 16;
  }
  if (permissionObject.annotating) {
    permissions |= 32;
  }
  return permissions;
};
var getPermissionsR3 = (permissionObject = {}) => {
  let permissions = 4294963392 >> 0;
  if (permissionObject.printing === "lowResolution" || permissionObject.printing) {
    permissions |= 4;
  }
  if (permissionObject.printing === "highResolution") {
    permissions |= 2052;
  }
  if (permissionObject.modifying) {
    permissions |= 8;
  }
  if (permissionObject.copying) {
    permissions |= 16;
  }
  if (permissionObject.annotating) {
    permissions |= 32;
  }
  if (permissionObject.fillingForms) {
    permissions |= 256;
  }
  if (permissionObject.contentAccessibility) {
    permissions |= 512;
  }
  if (permissionObject.documentAssembly) {
    permissions |= 1024;
  }
  return permissions;
};
var getUserPasswordR2 = (encryptionKey) => CryptoJS.RC4.encrypt(processPasswordR2R3R4(), encryptionKey).ciphertext;
var getUserPasswordR3R4 = (documentId, encryptionKey) => {
  const key = encryptionKey.clone();
  let cipher = CryptoJS.MD5(
    processPasswordR2R3R4().concat(
      CryptoJS.lib.WordArray.create(documentId)
    )
  );
  for (let i = 0; i < 20; i++) {
    const xorRound = Math.ceil(key.sigBytes / 4);
    for (let j = 0; j < xorRound; j++) {
      key.words[j] = encryptionKey.words[j] ^ (i | i << 8 | i << 16 | i << 24);
    }
    cipher = CryptoJS.RC4.encrypt(cipher, key).ciphertext;
  }
  return cipher.concat(
    CryptoJS.lib.WordArray.create(null, 16)
  );
};
var getOwnerPasswordR2R3R4 = (r, keyBits, paddedUserPassword, paddedOwnerPassword) => {
  let digest = paddedOwnerPassword;
  let round = r >= 3 ? 51 : 1;
  for (let i = 0; i < round; i++) {
    digest = CryptoJS.MD5(digest);
  }
  const key = digest.clone();
  key.sigBytes = keyBits / 8;
  let cipher = paddedUserPassword;
  round = r >= 3 ? 20 : 1;
  for (let i = 0; i < round; i++) {
    const xorRound = Math.ceil(key.sigBytes / 4);
    for (let j = 0; j < xorRound; j++) {
      key.words[j] = digest.words[j] ^ (i | i << 8 | i << 16 | i << 24);
    }
    cipher = CryptoJS.RC4.encrypt(cipher, key).ciphertext;
  }
  return cipher;
};
var decryptOpram = (r, keyBits, O, paddedOwnerPassword) => {
  let digest = paddedOwnerPassword;
  let round = r >= 3 ? 51 : 1;
  for (let i = 0; i < round; i++) {
    digest = CryptoJS.MD5(digest);
  }
  const key = digest.clone();
  key.sigBytes = keyBits / 8;
  let cipher = O;
  round = r >= 3 ? 20 : 1;
  for (let i = 0; i < round; i++) {
    const xorRound = Math.ceil(key.sigBytes / 4);
    for (let j = 0; j < xorRound; j++) {
      key.words[j] = digest.words[j] ^ (i | i << 8 | i << 16 | i << 24);
    }
    const pram = CryptoJS.lib.CipherParams.create({
      ciphertext: cipher
    });
    cipher = CryptoJS.RC4.decrypt(pram, key);
  }
  return cipher;
};
var getEncryptionKeyR2R3R4 = (r, keyBits, documentId, paddedUserPassword, ownerPasswordEntry, permissions, encryptMetadata = true) => {
  let key = paddedUserPassword.clone().concat(ownerPasswordEntry).concat(CryptoJS.lib.WordArray.create([lsbFirstWord(permissions)], 4)).concat(CryptoJS.lib.WordArray.create(documentId));
  if (r === 4 && !encryptMetadata) {
    key.concat(CryptoJS.lib.WordArray.create([4294967295]));
  }
  const round = r >= 3 ? 51 : 1;
  for (let i = 0; i < round; i++) {
    key = CryptoJS.MD5(key);
    key.sigBytes = keyBits / 8;
  }
  return key;
};
var processPasswordR2R3R4 = (password = "") => {
  const out = new Uint8Array(32);
  const length = password.length;
  let index = 0;
  while (index < length && index < 32) {
    const code = password.charCodeAt(index);
    if (code > 255) {
      throw new Error("Password contains one or more invalid characters.");
    }
    out[index] = code;
    index++;
  }
  while (index < 32) {
    out[index] = PASSWORD_PADDING[index - length];
    index++;
  }
  return CryptoJS.lib.WordArray.create(out);
};
var lsbFirstWord = (data) => (data & 255) << 24 | (data & 65280) << 8 | data >> 8 & 65280 | data >> 24 & 255;
var wordArrayToBuffer = (wordArray) => {
  const byteArray = [];
  for (let i = 0; i < wordArray.sigBytes; i++) {
    byteArray.push(
      wordArray.words[Math.floor(i / 4)] >> 8 * (3 - i % 4) & 255
    );
  }
  return Uint8Array.from(byteArray);
};
var checkUserpassword = (pram) => {
  if (pram.version <= 4) {
    if (pram.securityRevision === 2 || pram.securityRevision === 3 || pram.securityRevision === 4) {
      const paddedUserPassword = processPasswordR2R3R4(
        pram.userPassword
      );
      const userAuth = userPasswordAuthV4({
        securityRevision: pram.securityRevision,
        keyLength: pram.keyLength,
        paddedUserPassword,
        permissionNo: pram.permissionNo,
        documentID: pram.documentID,
        encryptMetadata: pram.encryptMetadata,
        O: pram.O
      });
      if (pram.U.subarray(0, 16).toString() === userAuth.U.subarray(0, 16).toString()) {
        return userAuth.key;
      }
      return;
    }
  } else if (pram.version === 5) {
    return;
  }
};
var userPasswordAuthV4 = (pram) => {
  const encryptionKey = getEncryptionKeyR2R3R4(
    pram.securityRevision,
    pram.keyLength,
    pram.documentID,
    pram.paddedUserPassword,
    CryptoJS.lib.WordArray.create(pram.O),
    pram.permissionNo,
    pram.securityRevision === 4 ? pram.encryptMetadata : true
  );
  let userPasswordEntry;
  if (pram.securityRevision === 2) {
    userPasswordEntry = getUserPasswordR2(encryptionKey);
  } else {
    userPasswordEntry = getUserPasswordR3R4(
      pram.documentID,
      encryptionKey
    );
  }
  return { U: wordArrayToBuffer(userPasswordEntry), key: encryptionKey };
};
var checkOwnerpassword = (pram) => {
  if (pram.version <= 4) {
    if (pram.securityRevision === 2 || pram.securityRevision === 3 || pram.securityRevision === 4) {
      const paddedOwnerPassword = processPasswordR2R3R4(pram.ownerPassword);
      const decryptedUserpassword = decryptOpram(pram.securityRevision, pram.keyLength, CryptoJS.lib.WordArray.create(pram.O), paddedOwnerPassword);
      const userAuth = userPasswordAuthV4({
        securityRevision: pram.securityRevision,
        keyLength: pram.keyLength,
        paddedUserPassword: decryptedUserpassword,
        permissionNo: pram.permissionNo,
        documentID: pram.documentID,
        encryptMetadata: pram.encryptMetadata,
        O: pram.O
      });
      if (pram.U.subarray(0, 16).toString() === userAuth.U.subarray(0, 16).toString()) {
        return userAuth.key;
      }
      return;
    }
  } else if (pram.version === 5) {
    return;
  }
};
var getDecryptFn = (version, encryptionKey, keyBits) => {
  return (encData, objectNumber, generetionNumber) => {
    const obj = objectNumber;
    const gen = generetionNumber;
    let digest;
    let key = CryptoJS.lib.WordArray.create();
    if (version < 5) {
      digest = encryptionKey.clone().concat(
        CryptoJS.lib.WordArray.create(
          [
            (obj & 255) << 24 | (obj & 65280) << 8 | obj >> 8 & 65280 | gen & 255,
            (gen & 65280) << 16
          ],
          5
        )
      );
      if (version === 1 || version === 2) {
        key = CryptoJS.MD5(digest);
        key.sigBytes = Math.min(16, keyBits / 8 + 5);
        const pram2 = CryptoJS.lib.CipherParams.create({
          ciphertext: CryptoJS.lib.WordArray.create(encData)
        });
        return wordArrayToBuffer(CryptoJS.RC4.decrypt(pram2, key));
      }
      if (version === 4) {
        key = CryptoJS.MD5(
          digest.concat(CryptoJS.lib.WordArray.create([1933667412], 4))
        );
      }
    } else if (version === 5) {
      key = encryptionKey;
    } else {
      throw new Error("Unknown V value");
    }
    const pram = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.lib.WordArray.create(encData.subarray(16))
    });
    const X = CryptoJS.AES.decrypt(pram, key, { "iv": CryptoJS.lib.WordArray.create(encData.subarray(0, 16)) });
    return wordArrayToBuffer(X);
  };
};
var _getEncryptFn = (obj, gen, version, keyBits, encryptionKey) => {
  let digest;
  let key;
  if (version < 5) {
    digest = encryptionKey.clone().concat(
      CryptoJS.lib.WordArray.create(
        [
          (obj & 255) << 24 | (obj & 65280) << 8 | obj >> 8 & 65280 | gen & 255,
          (gen & 65280) << 16
        ],
        5
      )
    );
    if (version === 1 || version === 2) {
      key = CryptoJS.MD5(digest);
      key.sigBytes = Math.min(16, keyBits / 8 + 5);
      return (buffer) => wordArrayToBuffer(
        CryptoJS.RC4.encrypt(
          CryptoJS.lib.WordArray.create(buffer),
          key
        ).ciphertext
      );
    }
    if (version === 4) {
      key = CryptoJS.MD5(
        digest.concat(CryptoJS.lib.WordArray.create([1933667412], 4))
      );
    }
  } else if (version === 5) {
    key = encryptionKey;
  } else {
    throw new Error("Unknown V value");
  }
  const iv = PDFSecurity.generateRandomWordArray(16);
  const options = {
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
    iv
  };
  return (buffer) => wordArrayToBuffer(
    iv.clone().concat(
      CryptoJS.AES.encrypt(
        CryptoJS.lib.WordArray.create(buffer),
        key,
        options
      ).ciphertext
    )
  );
};
var PASSWORD_PADDING = [
  40,
  191,
  78,
  94,
  78,
  117,
  138,
  65,
  100,
  0,
  78,
  86,
  255,
  250,
  1,
  8,
  46,
  46,
  0,
  182,
  208,
  104,
  62,
  128,
  47,
  12,
  169,
  254,
  100,
  83,
  105,
  122
];

// src/pdf-lib_patch.ts
var import_pdf_lib5 = require("pdf-lib");
var PDFDocument = import_pdf_lib5.PDFDocument;
var pdf_lib_Patch = {
  PDFString_SupportUTF16: (_PDFString) => {
    _PDFString.prototype.sizeInBytes = function() {
      return stringEncode(this.value, this._noEncode).length + 2;
    };
    _PDFString.prototype.copyBytesInto = function(buffer, offset) {
      buffer[offset++] = import_pdf_lib3.CharCodes.LeftParen;
      offset += copyStringIntoBuffer(this.value, buffer, offset, this._noEncode);
      buffer[offset++] = import_pdf_lib3.CharCodes.RightParen;
      return this.sizeInBytes();
    };
  },
  _BaseParserPatch: (_bytes) => {
    _bytes.moveTOP = function() {
      this.line = 0;
      this.column = 0;
      this.idx = 0;
    };
    _bytes.moveEND = function() {
      while (!this.done()) {
        this.next();
      }
    };
    _bytes.prev = function() {
      const byte = this.bytes[this.idx--];
      if (byte === import_pdf_lib3.CharCodes.Newline) {
        this.line -= 1;
        this.column = 0;
      } else {
        this.column -= 1;
      }
      return byte;
    };
  },
  SupportEncrypt: (_PDFParser, _PDFDocument3, _PDFXRefStreamParser) => {
    _PDFParser.prototype.parseStartxref = function(endOffset) {
      this.bytes.moveTo(endOffset);
      let offset = this.bytes.offset();
      while (offset > 0) {
        this.bytes.prev();
        offset = this.bytes.offset();
        const trailer = this.matchKeyword(Keywords.startxref);
        if (!trailer) {
          this.bytes.moveTo(offset);
        } else {
          offset = this.bytes.offset();
          this.skipWhitespaceAndComments();
          const xrefoffset = this.parseRawInt();
          this.skipWhitespace();
          this.matchKeyword(Keywords.eof);
          this.bytes.moveTo(offset - Keywords.startxref.length);
          return xrefoffset;
        }
      }
    };
    _PDFParser.prototype.parseTrailer = function(endOffset) {
      this.bytes.moveTo(endOffset);
      let offset = this.bytes.offset();
      while (offset > 0 && !this.bytes.done()) {
        this.bytes.next();
        offset = this.bytes.offset();
        const trailer = this.matchKeyword(Keywords.trailer);
        if (!trailer) {
          this.bytes.moveTo(offset);
        } else {
          offset = this.bytes.offset();
          this.skipWhitespaceAndComments();
          const dict = this.parseDict();
          this.bytes.moveTo(offset - Keywords.trailer.length);
          return {
            Root: dict.get(import_pdf_lib2.PDFName.of("Root")),
            Encrypt: dict.get(import_pdf_lib2.PDFName.of("Encrypt")),
            Info: dict.get(import_pdf_lib2.PDFName.of("Info")),
            ID: dict.get(import_pdf_lib2.PDFName.of("ID")),
            Prev: dict.get(import_pdf_lib2.PDFName.of("Prev")),
            XRefStm: dict.get(import_pdf_lib2.PDFName.of("XRefStm"))
          };
        }
      }
    };
    _PDFParser.prototype.parseTrailerXRefStm = function(offset) {
      this.bytes.moveTo(offset);
      this.skipWhitespaceAndComments();
      this.parseIndirectObjectHeader();
      this.skipWhitespaceAndComments();
      const object = this.parseObject();
      return import_pdf_lib4.PDFXRefStreamParser.forStream(object).parseEntries();
    };
    _PDFParser.prototype.parseCrossRefSection = function(startOffset) {
      return __async(this, null, function* () {
        const refEntries = [];
        let offset = this.bytes.offset();
        this.bytes.moveTo(startOffset);
        this.skipWhitespaceAndComments();
        this.bytes.moveTo(startOffset);
        const xrefKeyword = this.matchKeyword(Keywords.xref);
        if (!xrefKeyword) {
          this.bytes.prev();
          this.skipWhitespaceAndComments();
          offset = this.bytes.offset();
          this.parseIndirectObjectHeader();
          this.skipWhitespaceAndComments();
          const dict = this.parseDict();
          this.bytes.moveTo(offset - Keywords.trailer.length);
          const trailer = {
            Root: dict.get(import_pdf_lib2.PDFName.of("Root")),
            Encrypt: dict.get(import_pdf_lib2.PDFName.of("Encrypt")),
            Info: dict.get(import_pdf_lib2.PDFName.of("Info")),
            ID: dict.get(import_pdf_lib2.PDFName.of("ID")),
            Prev: dict.get(import_pdf_lib2.PDFName.of("Prev")),
            XRefStm: dict.get(import_pdf_lib2.PDFName.of("XRefStm"))
          };
          if (trailer && Object.keys(this.context.trailerInfo).length === 0) {
            this.context.trailerInfo = trailer;
          }
          const entries = this.parseTrailerXRefStm(offset);
          for (const entry of entries) {
            if (!refEntries.find((v) => {
              if (v.ref.generationNumber === entry.ref.objectNumber) {
                return true;
              }
            })) {
              refEntries.push(entry);
            }
          }
        } else if (xrefKeyword) {
          offset = this.bytes.offset();
          const trailer = this.parseTrailer(offset);
          if (trailer && Object.keys(this.context.trailerInfo).length === 0) {
            this.context.trailerInfo = trailer;
          }
          if (trailer.XRefStm && trailer.XRefStm instanceof import_pdf_lib2.PDFNumber) {
            offset = this.bytes.offset();
            const entries2 = this.parseTrailerXRefStm(trailer.XRefStm.asNumber());
            for (const entry of entries2) {
              if (!refEntries.find((v) => {
                if (v.ref.generationNumber === entry.ref.objectNumber) {
                  return true;
                }
              })) {
                refEntries.push(entry);
              }
            }
          }
          if (trailer == null ? void 0 : trailer.Prev) {
            offset = this.bytes.offset();
            const entries2 = yield this.parseCrossRefSection(trailer.Prev.asNumber());
            for (const entry of entries2) {
              if (!refEntries.find((v) => {
                if (v.ref.generationNumber === entry.ref.objectNumber) {
                  return true;
                }
              })) {
                refEntries.push(entry);
              }
            }
            this.bytes.moveTo(offset);
          }
          this.bytes.moveTo(offset);
          this.skipWhitespaceAndComments();
          let objectNumber = -1;
          const entries = [];
          while (!this.bytes.done() && this.bytes.peek() >= 48 && this.bytes.peek() <= 57) {
            const firstInt = this.parseRawInt();
            this.skipWhitespaceAndComments();
            const secondInt = this.parseRawInt();
            this.skipWhitespaceAndComments();
            const byte = this.bytes.peek();
            if (byte === import_pdf_lib3.CharCodes.n || byte === import_pdf_lib3.CharCodes.f) {
              const ref = import_pdf_lib2.PDFRef.of(objectNumber, secondInt);
              const del = this.bytes.next();
              entries.push({
                ref,
                inObjectStream: false,
                deleted: del === import_pdf_lib3.CharCodes.f ? true : false,
                offset: firstInt
              });
              objectNumber += 1;
            } else {
              objectNumber = firstInt;
            }
            this.skipWhitespaceAndComments();
          }
          for (const entry of entries) {
            if (!refEntries.find((v) => {
              if (v.ref.generationNumber === entry.ref.objectNumber) {
                return true;
              }
            })) {
              refEntries.push(entry);
            }
          }
        } else {
          throw new Error("Cross-Reference unsupport format.");
        }
        return refEntries;
      });
    };
    _PDFParser.prototype.parseDocument = function(security) {
      return __async(this, null, function* () {
        if (this.alreadyParsed) {
          throw new import_pdf_lib3.ReparseError("PDFParser", "parseDocument");
        }
        pdf_lib_Patch._BaseParserPatch(this.bytes);
        this.alreadyParsed = true;
        this.context.header = this.parseHeader();
        const bodyStartOffset = this.bytes.offset();
        this.bytes.moveEND();
        const refEntries = [];
        while (this.bytes.offset() > 0) {
          const startxref = this.parseStartxref(this.bytes.offset());
          if (startxref) {
            const entries = yield this.parseCrossRefSection(startxref);
            for (const entry of entries) {
              if (!refEntries.find((v) => {
                if (v.ref.generationNumber === entry.ref.objectNumber) {
                  return true;
                }
              })) {
                refEntries.push(entry);
              }
            }
          }
          this.bytes.prev();
        }
        if (this.context.trailerInfo.Encrypt) {
          if (this.context.trailerInfo.Encrypt instanceof import_pdf_lib2.PDFRef) {
            const encryptXref = refEntries.find((v) => {
              if (this.context.trailerInfo.Encrypt.objectNumber === v.ref.objectNumber) {
                return true;
              }
            });
            if (!encryptXref) {
              throw Error("Encrypt dic not found on CrossReferenceTable");
            }
            this.bytes.moveTo(encryptXref.offset);
            this.skipWhitespaceAndComments();
            this.parseIndirectObjectHeader();
            this.skipWhitespaceAndComments();
            const edict = this.parseDict();
            const decrypter = PDFSecurity.decrypter(edict, this.context, (security == null ? void 0 : security.password) || "", security == null ? void 0 : security.reqPermissions);
            this.context._reEncrypt = decrypter.reEncrypt;
            this._decrypter = decrypter.decrypt;
          }
        }
        const encrypt = this.context.trailerInfo.Encrypt;
        this.context._encrypt = encrypt;
        this.bytes.moveTo(bodyStartOffset);
        let prevOffset;
        while (!this.bytes.done()) {
          yield this.parseDocumentSection();
          const offset = this.bytes.offset();
          if (offset === prevOffset) {
            throw new import_pdf_lib3.StalledParserError(this.bytes.position());
          }
          prevOffset = offset;
        }
        this.maybeRecoverRoot();
        if (this.context._encrypt) {
          delete this.context.trailerInfo.Encrypt;
        }
        if (this.context.lookup(import_pdf_lib2.PDFRef.of(0))) {
          this.context.delete(import_pdf_lib2.PDFRef.of(0));
        }
        return this.context;
      });
    };
    _PDFParser.prototype.decryptValue = function(ref, object) {
      return __async(this, null, function* () {
        const decrypter = this._decrypter;
        if (object instanceof import_pdf_lib2.PDFDict) {
          const type = object.dict.get(import_pdf_lib2.PDFName.of("Type"));
          for (const value of object.dict) {
            if (((type == null ? void 0 : type.asString()) === "/Sig" || (type == null ? void 0 : type.asString()) === "/DocTimeStamp") && value[0].asString() === "/Contents") {
              continue;
            }
            if (value[1] instanceof import_pdf_lib2.PDFString) {
              const valueBuffer = value[1].asBytes();
              const data = decrypter(valueBuffer, ref.objectNumber, ref.generationNumber);
              if (value[0].asString() === "/Cert") {
                object.set(import_pdf_lib2.PDFName.of("Cert"), new import_pdf_lib2.PDFHexString(buffer2Hex(data)));
              } else {
                value[1].value = buffer2Str(data);
              }
            } else if (value[1] instanceof import_pdf_lib2.PDFHexString) {
              const valueBuffer = value[1].asBytes();
              const data = decrypter(valueBuffer, ref.objectNumber, ref.generationNumber);
              value[1].value = buffer2Hex(data);
            }
            if (value[1] instanceof import_pdf_lib2.PDFArray) {
              for (const item of value[1].asArray()) {
                yield this.decryptValue(ref, item);
              }
            }
            if (value[1] instanceof import_pdf_lib2.PDFDict) {
              yield this.decryptValue(ref, value[1]);
            }
          }
        }
        if (object instanceof import_pdf_lib2.PDFRawStream) {
          const valueBuffer = object.asUint8Array();
          const data = decrypter(valueBuffer, ref.objectNumber, ref.generationNumber);
          object.contents = data;
        }
        if (object instanceof import_pdf_lib2.PDFContentStream) {
          const valueBuffer = object.getContents();
          const data = decrypter(valueBuffer, ref.objectNumber, ref.generationNumber);
          object.contentsCache.value = data;
        }
      });
    };
    _PDFParser.prototype.parseIndirectObject = function() {
      return __async(this, null, function* () {
        var _a;
        const ref = this.parseIndirectObjectHeader();
        this.skipWhitespaceAndComments();
        const object = this.parseObject();
        if (this.context._encrypt instanceof import_pdf_lib2.PDFRef && this._decrypter) {
          const encryptDicRef = this.context._encrypt;
          const type = (_a = object.dict) == null ? void 0 : _a.get(import_pdf_lib2.PDFName.of("Type"));
          if ((type == null ? void 0 : type.toString()) !== "/XRef" && encryptDicRef.objectNumber !== ref.objectNumber) {
            yield this.decryptValue(ref, object);
          }
        }
        this.skipWhitespaceAndComments();
        this.matchKeyword(Keywords.endobj);
        if (object instanceof import_pdf_lib2.PDFRawStream && object.dict.lookup(import_pdf_lib2.PDFName.of("Type")) === import_pdf_lib2.PDFName.of("ObjStm")) {
          yield import_pdf_lib4.PDFObjectStreamParser.forStream(
            object,
            this.shouldWaitForTick
          ).parseIntoContext();
        } else if (object instanceof import_pdf_lib2.PDFRawStream && object.dict.lookup(import_pdf_lib2.PDFName.of("Type")) === import_pdf_lib2.PDFName.of("XRef")) {
          import_pdf_lib4.PDFXRefStreamParser.forStream(object).parseIntoContext();
        } else {
          this.context.assign(ref, object);
        }
        return ref;
      });
    };
    _PDFParser.prototype.jumpNextBody = function() {
      this.skipWhitespaceAndComments();
      while (!this.matchKeyword(Keywords.eof) && !this.bytes.done()) {
        this.bytes.next();
      }
    };
    _PDFParser.prototype.parseDocumentSection = function() {
      return __async(this, null, function* () {
        yield this.parseIndirectObjects();
        this.jumpNextBody();
        this.skipJibberish();
      });
    };
    _PDFXRefStreamParser.prototype.parseEntries = function() {
      const entries = [];
      const [typeFieldWidth, offsetFieldWidth, genFieldWidth] = this.byteWidths;
      const DecodeParms = this.dict.get(import_pdf_lib2.PDFName.of("DecodeParms"));
      if (DecodeParms instanceof import_pdf_lib2.PDFDict) {
        const Predictor = DecodeParms.get(import_pdf_lib2.PDFName.of("Predictor"));
        const Columns = DecodeParms.get(import_pdf_lib2.PDFName.of("Columns"));
        if (Predictor instanceof import_pdf_lib2.PDFNumber && Columns instanceof import_pdf_lib2.PDFNumber) {
          const predictorType = Predictor.asNumber();
          const columnNum = Columns.asNumber();
          this.bytes.bytes = predictor(this.bytes.slice(0, this.bytes.length), predictorType, columnNum);
        }
      }
      for (let subsectionIdx = 0, subsectionLen = this.subsections.length; subsectionIdx < subsectionLen; subsectionIdx++) {
        const { firstObjectNumber, length } = this.subsections[subsectionIdx];
        for (let objIdx = 0; objIdx < length; objIdx++) {
          let type = 0;
          for (let idx = 0, len = typeFieldWidth; idx < len; idx++) {
            type = type << 8 | this.bytes.next();
          }
          let offset = 0;
          for (let idx = 0, len = offsetFieldWidth; idx < len; idx++) {
            offset = offset << 8 | this.bytes.next();
          }
          let generationNumber = 0;
          for (let idx = 0, len = genFieldWidth; idx < len; idx++) {
            generationNumber = generationNumber << 8 | this.bytes.next();
          }
          if (typeFieldWidth === 0)
            type = 1;
          const objectNumber = firstObjectNumber + objIdx;
          const entry = {
            ref: import_pdf_lib2.PDFRef.of(objectNumber, generationNumber),
            offset,
            deleted: type === 0,
            inObjectStream: type === 2
          };
          entries.push(entry);
        }
      }
      return entries;
    };
    _PDFDocument3.load = function(_0) {
      return __async(this, arguments, function* (pdf, options = {}) {
        const {
          ignoreEncryption = false,
          parseSpeed = import_pdf_lib3.ParseSpeeds.Slow,
          throwOnInvalidObject = false,
          updateMetadata = true,
          capNumbers = false
        } = options;
        (0, import_pdf_lib3.assertIs)(pdf, "pdf", ["string", Uint8Array, ArrayBuffer]);
        (0, import_pdf_lib3.assertIs)(ignoreEncryption, "ignoreEncryption", ["boolean"]);
        (0, import_pdf_lib3.assertIs)(parseSpeed, "parseSpeed", ["number"]);
        (0, import_pdf_lib3.assertIs)(throwOnInvalidObject, "throwOnInvalidObject", ["boolean"]);
        const bytes = (0, import_pdf_lib3.toUint8Array)(pdf);
        const context = yield import_pdf_lib4.PDFParser.forBytesWithOptions(
          bytes,
          parseSpeed,
          throwOnInvalidObject,
          capNumbers
          //@ts-ignore
        ).parseDocument({ password: options == null ? void 0 : options.password, reqPermissions: options == null ? void 0 : options.reqPermissions });
        const pdfDocument = new PDFDocument(context, ignoreEncryption, updateMetadata);
        if (pdfDocument.context._encrypt && !options.unRemoveEncryptDic) {
          pdfDocument.context.delete(pdfDocument.context._encrypt);
          let maxObjectNumber = 0;
          for (const object of pdfDocument.context.enumerateIndirectObjects()) {
            maxObjectNumber = Math.max(maxObjectNumber, object[0].objectNumber);
          }
          pdfDocument.context.largestObjectNumber = maxObjectNumber;
        }
        return pdfDocument;
      });
    };
  }
};
var predictor = (buffer, type, column) => {
  const rows = [];
  const rowLength = Math.ceil(buffer.length / (column + 1));
  for (let idx = 0; idx < rowLength; idx++) {
    rows.push(buffer.subarray(idx * (column + 1), (idx + 1) * (column + 1)));
  }
  let length = column;
  for (let row = 0; row < rows.length; row++) {
    const filterType = rows[row][0];
    if (filterType === 1) {
      for (let clm = 2; clm < rows[row].length; clm++) {
        if (typeof rows[row][clm] === "number") {
          length++;
          rows[row][clm] = rows[row][clm] + rows[row][clm - 1];
        }
      }
    }
    if (filterType === 2 && row > 0) {
      for (let clm = 1; clm < rows[row].length; clm++) {
        if (typeof rows[row][clm] === "number") {
          length++;
          rows[row][clm] = rows[row][clm] + rows[row - 1][clm];
        }
      }
    }
    if (type === 3) {
      for (let clm = 1; clm < rows[row].length; clm++) {
        const left = clm > 2 ? rows[row][clm - 1] : 0;
        const up = row > 0 ? rows[row - 1][clm] : 0;
        if (typeof rows[row][clm] === "number") {
          length++;
          rows[row][clm] = rows[row][clm] + Math.floor((left + up) / 2);
        }
      }
    }
    if (type === 4) {
      for (let clm = 1; clm < rows[row].length; clm++) {
        const left = clm > 2 ? rows[row][clm - 1] : 0;
        const up = row > 0 ? rows[row - 1][clm] : 0;
        const upleft = clm > 2 && row > 0 ? rows[row - 1][clm] : 0;
        if (typeof rows[row][clm] === "number") {
          length++;
          rows[row][clm] = paethPredictor(left, up, upleft);
        }
      }
    }
  }
  const rawData = new Uint8Array(length);
  let pos = 0;
  let l = 0;
  for (const row of rows.map((v) => v.slice(1))) {
    rawData.set(row, pos);
    pos += column;
    l++;
  }
  return rawData;
};
var paethPredictor = (left, up, upleft) => {
  const p = left + up + upleft;
  const pa = Math.abs(p - left);
  const pb = Math.abs(p - up);
  const pc = Math.abs(p - upleft);
  return Math.min(pa, pb, pc);
};
var copyStringIntoBuffer = (str, buffer, offset, noEncode) => {
  const encStr = stringEncode(str, noEncode);
  const length = encStr.length;
  for (let idx = 0; idx < length; idx++) {
    buffer[offset++] = encStr[idx];
  }
  return length;
};
var stringEncode = (str, noEncode) => {
  if (noEncode || checkSingleByteCode(str)) {
    return new Uint8Array(Array.from(str).map((v) => v.charCodeAt(0)));
  }
  if (str.charCodeAt(0) === 254 && str.charCodeAt(1) === 255) {
    return new Uint8Array(Array.from(str).map((v) => v.charCodeAt(0)));
  }
  return stringToUTF16(str, "BE", true);
};
var checkSingleByteCode = (str) => {
  for (const c of Array.from(str)) {
    if ((c.codePointAt(0) || 256) > 128) {
      return false;
    }
  }
  return true;
};
var stringToUTF16 = (str, byteOrder, BOM) => {
  const buffer = new Uint8Array(str.length * 2 + (BOM ? 2 : 0));
  let pos = 0;
  if (BOM) {
    if (byteOrder === "BE") {
      buffer[0] = 254;
      buffer[1] = 255;
    } else {
      buffer[0] = 254;
      buffer[1] = 255;
    }
    pos = 2;
  }
  for (const char of Array.from(str)) {
    const codePoint = char.codePointAt(0);
    if (codePoint) {
      if (codePoint <= 65535) {
        buffer.set(get16to8(codePoint, byteOrder), pos);
        pos += 2;
      } else if (codePoint <= 1114111) {
        const h = ((codePoint - 65536 & 1047552) >> 10) + 55296;
        buffer.set(get16to8(h, byteOrder), pos);
        pos += 2;
        const l = (codePoint & 1023) + 56320;
        buffer.set(get16to8(l, byteOrder), pos);
        pos += 2;
      }
    }
  }
  return buffer;
};
var get16to8 = (word, order) => {
  if (order === "BE") {
    return new Uint8Array([(word & 65280) >> 8, word & 255]);
  } else {
    return new Uint8Array([word & 255, (word & 65280) >> 8]);
  }
};
var { Space, CarriageReturn, Newline } = import_pdf_lib3.CharCodes;
var stream = [
  import_pdf_lib3.CharCodes.s,
  import_pdf_lib3.CharCodes.t,
  import_pdf_lib3.CharCodes.r,
  import_pdf_lib3.CharCodes.e,
  import_pdf_lib3.CharCodes.a,
  import_pdf_lib3.CharCodes.m
];
var endstream = [
  import_pdf_lib3.CharCodes.e,
  import_pdf_lib3.CharCodes.n,
  import_pdf_lib3.CharCodes.d,
  import_pdf_lib3.CharCodes.s,
  import_pdf_lib3.CharCodes.t,
  import_pdf_lib3.CharCodes.r,
  import_pdf_lib3.CharCodes.e,
  import_pdf_lib3.CharCodes.a,
  import_pdf_lib3.CharCodes.m
];
var Keywords = {
  header: [
    import_pdf_lib3.CharCodes.Percent,
    import_pdf_lib3.CharCodes.P,
    import_pdf_lib3.CharCodes.D,
    import_pdf_lib3.CharCodes.F,
    import_pdf_lib3.CharCodes.Dash
  ],
  eof: [
    import_pdf_lib3.CharCodes.Percent,
    import_pdf_lib3.CharCodes.Percent,
    import_pdf_lib3.CharCodes.E,
    import_pdf_lib3.CharCodes.O,
    import_pdf_lib3.CharCodes.F
  ],
  obj: [import_pdf_lib3.CharCodes.o, import_pdf_lib3.CharCodes.b, import_pdf_lib3.CharCodes.j],
  endobj: [
    import_pdf_lib3.CharCodes.e,
    import_pdf_lib3.CharCodes.n,
    import_pdf_lib3.CharCodes.d,
    import_pdf_lib3.CharCodes.o,
    import_pdf_lib3.CharCodes.b,
    import_pdf_lib3.CharCodes.j
  ],
  xref: [import_pdf_lib3.CharCodes.x, import_pdf_lib3.CharCodes.r, import_pdf_lib3.CharCodes.e, import_pdf_lib3.CharCodes.f],
  trailer: [
    import_pdf_lib3.CharCodes.t,
    import_pdf_lib3.CharCodes.r,
    import_pdf_lib3.CharCodes.a,
    import_pdf_lib3.CharCodes.i,
    import_pdf_lib3.CharCodes.l,
    import_pdf_lib3.CharCodes.e,
    import_pdf_lib3.CharCodes.r
  ],
  startxref: [
    import_pdf_lib3.CharCodes.s,
    import_pdf_lib3.CharCodes.t,
    import_pdf_lib3.CharCodes.a,
    import_pdf_lib3.CharCodes.r,
    import_pdf_lib3.CharCodes.t,
    import_pdf_lib3.CharCodes.x,
    import_pdf_lib3.CharCodes.r,
    import_pdf_lib3.CharCodes.e,
    import_pdf_lib3.CharCodes.f
  ],
  true: [import_pdf_lib3.CharCodes.t, import_pdf_lib3.CharCodes.r, import_pdf_lib3.CharCodes.u, import_pdf_lib3.CharCodes.e],
  false: [import_pdf_lib3.CharCodes.f, import_pdf_lib3.CharCodes.a, import_pdf_lib3.CharCodes.l, import_pdf_lib3.CharCodes.s, import_pdf_lib3.CharCodes.e],
  null: [import_pdf_lib3.CharCodes.n, import_pdf_lib3.CharCodes.u, import_pdf_lib3.CharCodes.l, import_pdf_lib3.CharCodes.l],
  stream,
  streamEOF1: [...stream, Space, CarriageReturn, Newline],
  streamEOF2: [...stream, CarriageReturn, Newline],
  streamEOF3: [...stream, CarriageReturn],
  streamEOF4: [...stream, Newline],
  endstream,
  EOF1endstream: [CarriageReturn, Newline, ...endstream],
  EOF2endstream: [CarriageReturn, ...endstream],
  EOF3endstream: [Newline, ...endstream]
};
var IsDigit = new Uint8Array(256);
(() => {
  pdf_lib_Patch.PDFString_SupportUTF16(import_pdf_lib2.PDFString);
  pdf_lib_Patch.SupportEncrypt(import_pdf_lib4.PDFParser, import_pdf_lib5.PDFDocument, import_pdf_lib4.PDFXRefStreamParser);
})();

// src/spdf.ts
var decryptPDF = (pdf, ownerPassword) => __async(void 0, null, function* () {
  const pdfDoc = yield PDFDocument.load(pdf, { "password": ownerPassword });
  return yield pdfDoc.save({ "useObjectStreams": false });
});
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  decryptPDF
});
