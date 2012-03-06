/**
 * This class provides simple PDP functionality 
 * using built-in access control policy for fixed Roles and Actions
 *
 */


package org.aaaarch.gaaapi.test;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.Vector;

import org.aaaarch.pdp.impl.PDPinputParser;
import org.aaaarch.pdp.test.impl.PDPgenResponse;

import com.sun.org.apache.regexp.internal.RE;

public class TestPDPlocal {

	//static Document document;

	public static boolean runRBEboolean(Vector context) throws Exception {

	  // Initialisation		
	  boolean result = false; 
	  String message = "Deny"; 
	  int money = 0;
	  int costaction1 = 100;
	  int creditlowlimit = (costaction1*120)/100;

	/// 
	String subjectID = context.get(0).toString();
	String role = context.get(1).toString();
	String subjctx = context.get(2).toString();
	String actionId = context.get(3).toString();
	String resourceId = context.get(4).toString();
	String credit = "1000"; // dummy test value
	
	List actions = new ArrayList();
	actions.add(actionId);

		// Echo
		System.out.println( "\nPDP.runRBE(vector) input context:" );
		System.out.println( "PDP Request received from user \"" + subjectID + "\""); 		System.out.println( "with role(s) \"" + role + "\"");
		System.out.println( "to perform action(s) \"" + actionId + "\"");  
		System.out.println( "in experiment \"" + subjctx + "\" on instrument \"" + resourceId + "\"" ); 
		System.out.println( "\nUsing hard-coded policy implementing access control table:" +
				"\n------------------*---------*----------*-------*--------" +
				"\nAction - Role     | analyst | customer | guest | admin" +
				"\n------------------*---------*----------*-------*--------" +
				"\nControlExperiment *    1          0         0      0" +
				"\nControlInstrument *    1          0         0      1" +
				"\nViewExperiment    *    1          1         1      0" +
				"\nViewArchive       *    1          1         0      1" +
				"\nAdminTask         *    0          0         0      1" +
				"\nStartSession      *    1          0         0      0" +
				"\nJoinSession       *    1          1         1      0" +
				"\n------------------*---------*----------*-------*--------" +
				"\nAction cost = 100 EUR; Credit limit = 120 EUR"); 		
	// Policy variables (normally defined by administrator)
	/* Typical policy table:
	 * 
		--------------------------------------------------------*
		Action\Role       * analyst * customer * guest * admin  * 
		------------------*---------*----------*-------*--------*
			
		ControlExperiment *    1          0         0      0
			
		ControlInstrument *    1          0         0      1
			
		ViewExperiment    *    1          1         1      0
			
		ViewArchive       *    1          1         0      1
			
		AdminTask         *    0          0         0      1
			
		StartSession      *    1          0         0      0
			
		StopSession       *    1          0         0      1
			
		JoinSession       *    1          1         1      0
			
		---------------------------------------------------------
	 */
		// Begin Control of the permission for the Subject to perform the Actions
		// Only actions and roles are (hard)coded
		System.out.println( "\nAccess control in progress..." );
		String status = null;	
			for( int j = 0; j < actions.size(); j++ ) 
			{
				//attrAction = action.getAttributeActionAt( j ).toString();
				String actionj = actions.get(j).toString();
				if ( actionj.equals("ControlExperiment") )
				{
					if ( role.equals("analyst") )
					{result = true; message = "Permit";}
					else 
					{
						if ( role.equals("customer") )
						{ result = false; message = "Deny";}
						else
						{
							if ( role.equals("guest") )
							{ result = false; message = "Deny";}
							else
							{
							if ( role.equals("admin") )
							{ result = false; message = "Deny";}
							else 
							{ result = false; status = "Role is not valid";
							System.out.println( status ); 
								returnMsg(result, message, status); /* TODO: returnMsg method*/
								}
							}
						}
					}
				}
				else 
				{
					if ( actionj.equals("ControlInstrument") )
					{
						if ( role.equals("analyst") )
						{result = true; message = "Permit";}
						else 
						{
							if ( role.equals("customer") )
							{ result = false; message = "Deny";}
							else
							{
								if ( role.equals("guest") )
								{ result = false; message = "Deny";}
								else
								{
								if ( role.equals("admin") )
								{ result = true; message = "Permit";}
								else 
								{ result = false; System.out.println( "Role is not valid" ); 
									returnMsg(result, message, status);
									}
								}
							}
						}
					}
					else
					{
						if ( actionj.equals("ViewExperiment") )
						{
							if ( role.equals("analyst") )
							{result = true; message = "Permit";}
							else 
							{
								if ( role.equals("customer") )
								{ result = true; message = "Permit";}
								else
								{
									if ( role.equals("guest") )
									{ result = true; message = "Permit";}
									else
									{
									if ( role.equals("admin") )
									{ result = false; message = "Deny";}
									else 
									{ result = false; 
										System.out.println( "Role is not valid" ); 
										returnMsg(result, message, status);}
									}
								}
							}
						}
						else 
						{
							if ( actionj.equals("ViewArchive") )
							{
								if ( role.equals("analyst") )
								{result = true; message = "Permit";}
								else 
								{
									if ( role.equals("customer") )
									{ result = true; message = "Permit";}
									else
									{
										if ( role.equals("guest") )
										{ result = false; message = "Deny";}
										else
										{
										if ( role.equals("admin") )
										{ result = false; message = "Deny";}
										else 
										{ result = false; 
											System.out.println( "Role is not valid" ); 
											returnMsg(result, message, status);}
										}
									}
								}
							}
							else
							{
								if ( actionj.equals("AdminTask") )
								{
									System.out.println( 
										"Action: " + actionj + 
										"; cost = " + costaction1 + " EUR"); 
									if ( role.equals("analyst") )
									{result = false; message = "Deny";}
									else 
									{
										if ( role.equals("customer") )
										{ result = false; message = "Deny";}
										else
										{
											if ( role.equals("guest") )
											{ result = false; message = "Deny";}
											else
											{
											if ( role.equals("admin") )
											{ result = true; message = "Permit";}
											else 
											{ result = false; 
												System.out.println( "Role is not valid" ); 
												returnMsg(result, message, status);}
											}
										}
									}
								}
							else 
							{
								if ( actionj.equals("StartSession") )
								{
									System.out.println( 
										"Action: " + actionj + 
										"; cost = " + costaction1 + " EUR"); 
									if ( role.equals("analyst") )
									{result = true; message = "Permit";}
									else 
									{
										if ( role.equals("customer") )
										{ result = false; message = "Deny";}
										else
										{
											if ( role.equals("guest") )
											{ result = false; message = "Deny";}
											else
											{
											if ( role.equals("admin") )
											{ result = false; message = "Deny";}
											else 
											{ result = false; 
												System.out.println( "Role is not valid" ); 
												returnMsg(result, message, status);}
											}
										}
									}
								} 
								else
								{
									if ( actionj.equals("StopSession") )
									{
										System.out.println( 
											"Action: " + actionj + 
											"; cost = " + costaction1 + " EUR"); 
										if ( role.equals("analyst") )
										{result = true; message = "Permit";}
										else 
										{
											if ( role.equals("customer") )
											{ result = false; message = "Deny";}
											else
											{
												if ( role.equals("guest") )
												{ result = false; message = "Deny";}
												else
												{
												if ( role.equals("admin") )
												{ result = true; message = "Permit";}
												else 
												{ 
													result = false; 
													System.out.println( "Role is not valid" ); 
													returnMsg(result, message, status);}
												}
											}
										}
									} 
									else 
									{
										if ( actionj.equals("JoinSession") )
										{
											if ( role.equals("analyst") )
											{result = true; message = "Permit";}
											else 
											{
												if ( role.equals("customer") )
												{ result = true; message = "Permit";}
												else
												{
													if ( role.equals("guest") )
													{ result = true; message = "Permit";}
													else
													{
														if ( role.equals("admin") )
														{ result = false; message = "Deny";}
														else 
														{ result = false; 
														System.out.println( "Role is not valid" ); 
														returnMsg(result, message, status);}
													}
												}
											}
										}
										else {result = false; message = "Deny";
											System.out.println( "Action is not valid" ); 
											returnMsg(result, message, status);
											}
									}
								}
							}
							//else {System.out.println( "Action is not valid" ); returnMsg(result, message, status);}
						}
					}
				}
			}
			System.out.println( "TestPDPlocal.runRBE(Request) Decision = " + message ); 
		}
		
		// End evaluation of the Action permission for the Role

		// Obligation execution should be related to PEP	
		if (result) 
		{
				//Place for parsing AttributeSubject to retrieve credit value
				//Parse for integer digital value
			for( int j = 0; j < actions.size(); j++ ) 
			{
				String actionj = actions.get(j).toString();
				System.out.println( "\nPolicy/Action obligations:" );
				System.out.println( "Action: " + actionj + "; cost = " + costaction1 + " EUR"); 
				
				RE r = new RE("\\d+");
				String line = credit;
				StringTokenizer st = new StringTokenizer (line);
				while (st.hasMoreTokens()) 
				{
					String strmoney = st.nextToken();
					//System.out.println("token: " + st.nextToken());
					//
					if (r.match(strmoney))
					{
						String credit1 = strmoney;
						money = Integer.parseInt(strmoney);
						//System.out.println("credit = " + money);
					}
				}

				if( money > creditlowlimit )
				{
					System.out.println( "Checking credit... Credit is OK: " + money + " EUR (just for test purposes)");
					// place for operations on credit

					money = money - costaction1;
				}
				else 
				{
					boolean result$ = false;
					String message$ = "Credit " + credit + " is not sufficient"; 
					System.out.println( 
						"Credit " + credit + 
						" is not sufficient" ); 
					returnMsg(result$, message$, status);
				}
				//perform obligations action, e.g. deduct cost of action
				//subject.getAttributeAt(4).replaceAttributeValueAt( "Credit = " + money + " EUR", 0 );
				System.out.println( "New credit: " + money + " EUR" ); 
			}
		}

	return result;
 }


public static boolean runRBEboolean(String requestString) throws Exception {

    // vector context = [subjectId, subjctx, role, actionId, resourceId, subjext]
	Vector context = PDPinputParser.parseXACMLRequest(requestString);	
	//System.out.println("\nPDP.runRBE Echo: Context Vector extracted from Request:\n" + context);

	boolean decision = runRBEboolean(context);

	return decision;
}
// Returns XACML Response as string
public static String requestRBExacmlResponse(String request) throws Exception {
	String resourceId = null;
	//////////
	Vector context = new Vector();
	context = PDPinputParser.parseXACMLRequest(request);	
	System.out.println("\nPDP Echo: Context extracted from the Request\n" + context);
	//TODO: runRBE to request by context
	//boolean result = runRBE(request);
	boolean result = runRBEboolean(context);

	String statusDetail = "DecisionID";
	String statusMsg = null;
	resourceId = context.get(4).toString();
	
	if( result ){
		statusMsg = "Request is successful";
	} else {		
		statusMsg = "Request failed"; 
	}
	
	String response = PDPgenResponse.genResponseString(result, statusDetail, statusMsg, resourceId);

	/// Echo printing
	System.out.println("\nPDP Echo: Response message to return\n" + response);
	
	return response;
}

private static void returnMsg(boolean result, String message, String status) {
	// TODO Separate Response message sending - to contact Sending class
	
}
	 
}
