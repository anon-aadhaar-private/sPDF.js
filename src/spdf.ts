import {PDFObject} from "pdf-lib";
import {PDFDocument} from "./pdf-lib_patch";

interface LiteralObject {
    [name: string]: Literal | PDFObject;
}
interface LiteralArray {
    [index: number]: Literal | PDFObject;
}
type Literal =
    | LiteralObject
    | LiteralArray
    | string
    | number
    | boolean
    | null
    | undefined;

export const decryptPDF = async (pdf: string | Uint8Array | ArrayBuffer,ownerPassword:string) => {
    const pdfDoc = await PDFDocument.load(pdf,{"password":ownerPassword});
    return await pdfDoc.save({"useObjectStreams":false});
}
