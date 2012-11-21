/**
 * System and Network Engineering Group
 * University of Amsterdam
 *
 */
package org.aaaarch.sunxacml;

import java.util.Iterator;
import java.util.List;
import java.util.Set;

import oasis.names.tc.xacml._2_0.context.schema.os.DecisionType;
import oasis.names.tc.xacml._2_0.context.schema.os.ObjectFactory;
import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;
import oasis.names.tc.xacml._2_0.context.schema.os.ResponseType;
import oasis.names.tc.xacml._2_0.context.schema.os.ResultType;
import oasis.names.tc.xacml._2_0.context.schema.os.StatusCodeType;
import oasis.names.tc.xacml._2_0.context.schema.os.StatusDetailType;
import oasis.names.tc.xacml._2_0.context.schema.os.StatusType;

import org.aaaarch.pdp.XACMLPDPAdapter;
import com.sun.xacml.PDP;
import com.sun.xacml.PDPConfig;
import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;
import com.sun.xacml.ctx.Status;

/**
 * @author Canh Ngo (t.c.ngo@uva.nl)
 * 
 * @version
 * @date: Mar 15, 2012
 */
public class SunXACMLPDPAdapter implements XACMLPDPAdapter {

	// private static final transient org.slf4j.Logger log =
	// org.slf4j.LoggerFactory
	// .getLogger(SunXACMLPDPAdapter.class);

	private static final transient java.util.logging.Logger log = java.util.logging.Logger
			.getLogger(SunXACMLPDPAdapter.class.getName());

	private PDP sunPDP;

	public SunXACMLPDPAdapter(PDPConfig config) {
		this.sunPDP = new PDP(config);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.aaaarch.pdp.XACMLPDPAdapter#evaluate(oasis.names.tc.xacml._2_0.context
	 * .schema.os.RequestType)
	 */
	public ResponseType evaluate(RequestType request) {

		ResponseCtx respCtx = sunPDP.evaluate(request);

		ResponseType resp = convertResponseCtx(respCtx);

		return resp;
	}

	/**
	 * Convert from ResponseCtx to JAXB ResponseType.
	 * 
	 * @param respCtx
	 * @return
	 */
	private ResponseType convertResponseCtx(ResponseCtx respCtx) {
		ResponseType resp = (new ObjectFactory()).createResponseType();
		List<ResultType> resultTypes = resp.getResult();

		Set results = respCtx.getResults();
		Iterator it = results.iterator();

		while (it.hasNext()) {
			Result result = (Result) it.next();
			resultTypes.add(convertResult(result));
		}

		return resp;
	}

	/**
	 * Convert from old Result class object to standard JAXB ResultType.
	 * 
	 * @param result
	 * @return
	 */
	private static ResultType convertResult(Result result) {
		ObjectFactory objFactory = new ObjectFactory();

		ResultType resultType = objFactory.createResultType();

		// set Decision
		switch (result.getDecision()) {
		case Result.DECISION_PERMIT:
			resultType.setDecision(DecisionType.PERMIT);
			break;
		case Result.DECISION_DENY:
			resultType.setDecision(DecisionType.DENY);
			break;
		case Result.DECISION_INDETERMINATE:
			resultType.setDecision(DecisionType.INDETERMINATE);
			break;
		case Result.DECISION_NOT_APPLICABLE:
			resultType.setDecision(DecisionType.NOT_APPLICABLE);
			break;
		}
		// set Resource-Id
		resultType.setResourceId(result.getResource());

		// set Status
		Status status = result.getStatus();

		// set StatusCode
		StatusType statusType = objFactory.createStatusType();
		StatusCodeType statusCodeType = objFactory.createStatusCodeType();
		statusCodeType.setValue((String) status.getCode().get(0));

		if (status.getDetail() != null) {
			// Set StatusDetail
			StatusDetailType statusDetailType = objFactory
					.createStatusDetailType();
			try {
				statusDetailType.getAny().add(status.getDetail().getDetail());
			} catch (Exception e) {
				e.printStackTrace();
			}
			statusType.setStatusDetail(statusDetailType);
		}

		statusType.setStatusCode(statusCodeType);
		statusType.setStatusMessage(status.getMessage());

		resultType.setStatus(statusType);
		// Ignore Obligations

		return resultType;
	}

}
