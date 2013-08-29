package org.apache.log4j;


//import org.apache.log4j.Level;
//import org.apache.log4j.Logger;  
    
    public class TestLog4J {  
    	public native String DEBUGlog(String msg);
    	//public native String INFOlog(String msg);
    	//public native String WARNGlog(String msg);
    	//public native String ERRORlog(String msg);
    	//public native String FATALlog(String msg);
    	
    	static Logger logger = Logger.getLogger(TestLog4J.class); 
        
    	public static void main(String[] args) {  
        	System.loadLibrary("libsyslogC");  
        	TestLog4J testlog4j =new TestLog4J();
        	//System.out.println("===");
        	//new TestLog4J().myMethodSay();
        	//}
       
        //public void myMethodSay(){
        	String debugMsg = testlog4j.DEBUGlog("a DEBUG msg for testing log4j");
        	logger.debug(debugMsg);
        	//String infoMsg = testlog4j.syslog();
        	//String warnMsg = testlog4j.syslog();
        	//String errorMsg = testlog4j.syslog();
        	//String fatalMsg = testlog4j.syslog();
        	
            /*this.logger.debug("a DEBUG msg for testing log4j");
            this.logger.info("an INFO msg for testing log4j");
            this.logger.warn("a WARN msg for testing log4j");
            this.logger.error("an ERROR msg for testing log4j");
            this.logger.fatal("a FATAL msg for testing log4j");     */                                     
        }  
      
    }  