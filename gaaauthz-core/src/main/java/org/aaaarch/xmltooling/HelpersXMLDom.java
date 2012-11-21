package org.aaaarch.xmltooling;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class HelpersXMLDom {

public static Document importDocumentToDocument(Document docOutput, Document docInput) {

	 Node nodeInput = docInput.getDocumentElement();
 	 Node nodeImported = docOutput.importNode(nodeInput,true);
 	 docOutput.getDocumentElement().appendChild(nodeImported);
 	 return docOutput;
}

public static Document importNodeToDocument(Document docOutput, Node nodeInput) {

	 Node nodeImported = docOutput.importNode(nodeInput,true);
	 docOutput.getDocumentElement().appendChild(nodeImported);
	 return docOutput;
}

public static Node importDocumentToNode(Node nodeOutput, Document docInput) {

	 Node nodeInput = docInput.getDocumentElement();
	 Node nodeImported = nodeOutput.getOwnerDocument().importNode(nodeInput,true);
	 nodeOutput.appendChild(nodeImported);
	 return nodeOutput;
}

public static Node importNodeToNode(Node nodeOutput, Node nodeInput) {

	 Node nodeImported = nodeOutput.getOwnerDocument().importNode(nodeInput,true);
	 nodeOutput.appendChild(nodeImported);
	 return nodeOutput;
}

}