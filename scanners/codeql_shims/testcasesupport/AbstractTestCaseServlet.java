/*
 * CARE-Sec build shim (Lane 3). Replaces Juliet's testcasesupport.AbstractTestCaseServlet
 * only inside the CodeQL build tree. See AbstractTestCase.java for why: the sanitized
 * servlet cases implement processRequest(request, response) instead of bad()/good().
 */
package testcasesupport;

import java.io.IOException;
import javax.servlet.http.*;

public abstract class AbstractTestCaseServlet extends AbstractTestCaseServletBase
{
    private static final long serialVersionUID = 1L;

    public abstract void processRequest(HttpServletRequest request,
            HttpServletResponse response) throws Throwable;

    public void runTest(HttpServletRequest request, HttpServletResponse response)
            throws IOException
    {
        String className = this.getClass().getName();
        String servletName = className.substring(className.lastIndexOf('.') + 1);
        response.getWriter().println("<br><br>Starting test for Servlet " + servletName);
        try
        {
            processRequest(request, response);
            response.getWriter().println("<br>Completed processRequest() for Servlet " + servletName);
        }
        catch (Throwable throwableException)
        {
            response.getWriter().println("<br>Caught throwable from processRequest() in Servlet " + servletName);
            response.getWriter().println("<br>Throwable's message = " + throwableException.getMessage());
        }
    }
}
