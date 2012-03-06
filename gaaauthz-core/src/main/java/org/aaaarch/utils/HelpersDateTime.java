/*
 * Created on Feb 6, 2005
 *
 */
package org.aaaarch.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * @author demch
 * Current TimeZone is : sun.util.calendar.ZoneInfo
 * [id="Europe/Berlin",offset=3600000,dstSavings=3600000,useDaylight=true,transitions=143,
 *   lastRule=java.util.SimpleTimeZone[id=Europe/Berlin,
 *   offset=3600000,dstSavings=3600000,useDaylight=true,startYear=0,startMode=2,
 *   startMonth=2,startDay=-1,startDayOfWeek=1,
 *   startTime=3600000,startTimeMode=2,endMode=2,endMonth=9,endDay=-1,endDayOfWeek=1,
 *   endTime=3600000,endTimeMode=2]]
 * 
 *
 */
public class HelpersDateTime {
	public static Date dateformat (String dateTime) throws ParseException {
        SimpleDateFormat formatter = null;
        //String dateTime = "2002-02-02T22:22:22Z";
        //String dateTime = "2002-02-02";
        int dot = dateTime.indexOf('.');
        int col = dateTime.indexOf(':');
        if (col > 0) {
        if (dot > 0) {
            formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        }
        else {
            formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        }} else{
            formatter = new SimpleDateFormat("yyyy-MM-dd");
        }
        //formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        Date dt = formatter.parse(dateTime);
		return dt;
	}

	public static String datetostring (Date dateInst) throws ParseException {
        //String dateTime = "2002-02-02T22:22:22Z";
        //String dateTime = "2002-02-02";
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        String dtstring = formatter.format(dateInst);

		return dtstring;
	}

}
