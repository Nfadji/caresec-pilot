/*
 * CARE-Sec build shim (Lane 3). Replaces Juliet's testcasesupport.AbstractTestCase
 * only inside the CodeQL build tree.
 *
 * Lane 1 sanitized the Juliet cases by collapsing their bad()/good() methods into a
 * single processRequest() so that method names cannot leak the label. The upstream
 * base class still declares bad() and good() abstract, so the sanitized cases would
 * not compile against it. This shim keeps the same package, superclass and runTest()
 * entry point but requires processRequest() instead.
 */
package testcasesupport;

public abstract class AbstractTestCase extends AbstractTestCaseBase
{
    public abstract void processRequest() throws Throwable;

    public void runTest(String className)
    {
        IO.writeLine("Starting test for Class " + className);
        try
        {
            processRequest();
            IO.writeLine("Completed processRequest() for Class " + className);
        }
        catch (Throwable throwableException)
        {
            IO.writeLine("Caught a throwable from processRequest() for Class " + className);
            IO.writeLine("Throwable's message = " + throwableException.getMessage());
        }
    }
}
