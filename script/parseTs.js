const ts = require('typescript');
const fs = require('fs');

function extractFunctionInfo(filePath) {
    const program = ts.createProgram([filePath], {});
    const checker = program.getTypeChecker();
    const functions = [];

    for (const sourceFile of program.getSourceFiles()) {
        if (!sourceFile.fileName.includes("Native.d.ts")){
            continue;
        }
        if (sourceFile.isDeclarationFile) {
            ts.forEachChild(sourceFile, visit);
        }
    }

    function visit(node) {
        switch (node.kind) {
            case ts.SyntaxKind.FunctionDeclaration:
                // const functionDeclaration = node as ts.FunctionDeclaration;
                const functionDeclaration = node;
                // console.log(`Function: ${functionDeclaration.name?.getText().replaceAll('_','.')}`);
                console.log(functionDeclaration.getText().replaceAll('_','.'));
                break;
            case ts.SyntaxKind.InterfaceDeclaration:
                // const interfaceDeclaration = node as ts.InterfaceDeclaration;
                const interfaceDeclaration = node;
                // console.log(`Interface: ${interfaceDeclaration.name.getText().replaceAll('_','.')}`);
                console.log(interfaceDeclaration.getText().replaceAll('_','.'));
                break;
            case ts.SyntaxKind.ClassDeclaration:
                // const classDeclaration = node as ts.ClassDeclaration;
                const classDeclaration = node;
                // console.log(`Class: ${classDeclaration.name?.getText().replaceAll('_','.')}`);
                console.log(classDeclaration.getText().replaceAll('_','.'));
                break;
            case ts.SyntaxKind.TypeAliasDeclaration:
                const alias = node;
                console.log(classDeclaration.getText().replaceAll('_','.'));
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
const functionsJson = JSON.stringify(functionsInfo, null, 2);
fs.writeFile('functionsInfo.json', functionsJson, (err) => {
    if (err) {
        console.error('Error writing file:', err);
    } else {
        console.log('Successfully wrote functions info to functionsInfo.json');
    }
});
