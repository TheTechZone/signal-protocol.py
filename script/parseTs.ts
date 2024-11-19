import * as ts from 'typescript';
import {writeFile} from "fs";
// import { readFileSync } from 'fs';

function _typeConvert(symbol: string): string {
    let pySymbol = symbol.replace(/Buffer/g, 'bytes');
    pySymbol = pySymbol.replace(/null/g, 'None');
    pySymbol = pySymbol.replace(/string/g, 'str');
    pySymbol = pySymbol.replace(/number/g, 'int');
    pySymbol = pySymbol.replace(/bigint/g, 'int');
    pySymbol = pySymbol.replace(/boolean/g, 'bool');
    pySymbol = pySymbol.replace(/void/g, 'None');

    // Replace TypeScript async return types with Python's async return types
    pySymbol = pySymbol.replace(/Promise<(.*?)>/g, 'Awaitable[$1]');

    pySymbol = pySymbol.replace(/<(.*?)>/g, "[$1]")


    return pySymbol;
}

// convert a ts type to something pseudo-python-ish
function convertTsToPython(tsFunction: string): string {
    // Replace TypeScript Buffer type with Python bytes
    let pythonFunction = _typeConvert(tsFunction);
    
    // Replace TypeScript void return type with Python None
    // pythonFunction = pythonFunction.replace(/void;/g, 'None');
    
    pythonFunction = pythonFunction.replace(/=>/g, '->');

    pythonFunction = pythonFunction.replace(/;/g, ':');

    // Convert TypeScript function declaration syntax to Python
    pythonFunction = pythonFunction.replace(/export function (.*?)\((.*?)\): (.*?);?/g, 
                          'def $1($2) -> $3');

    
    return pythonFunction + " ...";
}

function convertTypeToPython(tyType: string): string {
    let pyType = _typeConvert(tyType);
    pyType = pyType.replace(/type (.*?) = (.*?);/g, '$1: TypeAlias = $2');
    pyType = pyType.replace(';','');
    return pyType;
}

function convertTsClassToPython(tsClass: string): string {
    // // Replace TypeScript async return types with Python's async return types
    // let pythonClass = tsClass.replace(/Promise<(.*?)>/g, 'Awaitable[$1]');
    let pythonClass = _typeConvert(tsClass);

    // Convert TypeScript method syntax to Python method syntax
    pythonClass = pythonClass.replace(/(\w+)\s+(\w+)\((.*?)\): (.*?);/g, 
                          'async def $2($3) -> $4:');
    
    pythonClass = pythonClass.replace(/ extends (\w+)/g, '($1)')
    // Convert TypeScript class syntax to Python class syntax
    pythonClass = pythonClass.replace(/export abstract class (\S+) \{/g, 
                          'class $1:');
    
    // Remove TypeScript-specific keywords
    pythonClass = pythonClass.replace(/export/g, '');
    pythonClass = pythonClass.replace(/abstract/g, '');
    
    pythonClass = pythonClass.replace('}', '');
    return pythonClass;
}



function extractFunctionInfo(filePath: string): string[] {
    const program = ts.createProgram([filePath], {});
    const checker = program.getTypeChecker();
    const functions: string[] = ["from typing import TypeAlias, Awaitable\n","class Wrapper: '''Read only '''"];

    for (const sourceFile of program.getSourceFiles()) {
        if (!sourceFile.fileName.includes("Native.d.ts")){
            continue;
        }
        if (sourceFile.isDeclarationFile) {
            ts.forEachChild(sourceFile, visit);
        }
    }

    function visit(node: ts.Node) {
        switch (node.kind) {
            case ts.SyntaxKind.FunctionDeclaration:
                const functionDeclaration = node as ts.FunctionDeclaration;                
                const pyFunc =  convertTsToPython(
                    functionDeclaration.getText()
                    // .replace('_','.')
                );
                functions.push(pyFunc);
                break;
            case ts.SyntaxKind.InterfaceDeclaration:
                /*
                const interfaceDeclaration = node as ts.InterfaceDeclaration;
                // console.log(`Interface: ${interfaceDeclaration.name.getText().replaceAll('_','.')}`);
                console.log(interfaceDeclaration.getText()
                    // .replace('_','.')
                );
                */

                break;
            case ts.SyntaxKind.ClassDeclaration:
                const classDeclaration = node as ts.ClassDeclaration;
                // console.log(`Class: ${classDeclaration.name?.getText().replaceAll('_','.')}`);
                const pyClass = convertTsClassToPython(classDeclaration.getText());
                    // .replace('_','.')
                functions.push(pyClass);
                break;
            case ts.SyntaxKind.TypeAliasDeclaration:
                const alias = node;
                const pyAlias = convertTypeToPython(alias.getText());
                functions.push(pyAlias);

        }


        // if (ts.isFunctionDeclaration(node)) {
        //     const signature = checker.getSignatureFromDeclaration(node);
        //     const parameters = signature.parameters.map(param => ({
        //         name: param.name,
        //         type: checker.typeToString(checker.getTypeOfSymbolAtLocation(param, param.valueDeclaration))
        //     }));
        //     functions.push({
        //         name: node.name?.getText(),
        //         parameters: parameters
        //     });
        // }
        ts.forEachChild(node, visit);
    }

    return functions;
}

const filePath = './Native.d.ts'; // Path to your TypeScript file
const functionsInfo = extractFunctionInfo(filePath);

// Convert the functions info to JSON and write it to a file
const jsSymbols = functionsInfo.join('\n\n');

writeFile('symbol.pseudo.py', jsSymbols, (err) => {
    if (err) {
        console.error('Error writing file:', err);
    } else {
        console.log('Successfully wrote data to symbol.pseudo.py');
    }
});
