# $language = "Python"
# $interface = "1.0"

# PasteWithEchoFlowControl.py
#
# Last Modified:
#     14 Apr, 2023
#       - Updated to support either python v2 or v3
#       - Updated to support UTF-8 encoding
#       - Add ability to turn on verbose reporting as the
#         script is running.
#
#     10 Aug, 2021
#       - Add code to prevent hangs from occurring when the
#         prior version of the script failed to account for
#         the width of the shell prompt (which resulted in
#         thinking that we had the entire width of the term
#         screen).
#
#   01 Jun, 2020
#       - Add code to detect long lines that would likely be
#         wrapped, and wait for such lines to be echo'd back
#         to us character by character since a long line
#         will likely have wrapped and be impossible to wait
#         for.
#
#   08 Dec, 2011
#     - Initial revision
#
# Description:
#   Demonstrates how to send a block of lines from the clipboard and
#   wait for each line to be echoed back by the remote host before the next
#   line is sent. This is one approach to prevent overwhelming a remote host
#   that cannot accept data as fast as SecureCRT normally sends it by making
#   sure the remote machine has received each block of lines before moving on
#   with the next block.

import SecureCRT
import time

crt.Screen.Synchronous = True
crt.Screen.IgnoreEscape = True

# If additional verbosity is desired (current state of the script displayed
# to SecureCRT's status bar), you can set the following g_bVerbose variable to
# True. It is set to False by default. Setting it to True will slow down
# overal operation of the script, since SecureCRT is being tasked with
# displaying text to its status bar (sometimes for every character being
# sent, depending on the length of the line).
g_bVerbose = False

def Debug(strMsg):
    global g_bVerbose
    if g_bVerbose:
        crt.Session.SetStatusText(strMsg)
    
def main():
    # If there isn't an active connection, there's no point in continuing
    # since we can't send data.
    if not crt.Session.Connected:
        crt.Dialog.MessageBox("Sending data requires an active connection.")
        return

    # If there isn't anything in the clipboard, it doesn't make any
    # sense to continue with the script.
    if crt.Clipboard.Text.strip() == "":
        crt.Dialog.MessageBox("No text found in the clipboard.")
        return


    # Keep timing information so that we can display how long it took for the
    # data to be sent to the remote (each line sent only after the prior line
    # was echo'd back to SecureCRT, as a flow control mechanism).
    nStartTime = time.time()

    # Multiple lines in the clipboard are typically stored with a CRLF
    # separator, but this script example tries to accommodate other line endings
    # that might be supported by some editors. Break up lines into an array
    # (each line as an element within the array).
    if crt.Clipboard.Text.find("\r\n") > -1:
        vLines = crt.Clipboard.Text.split("\r\n")
    elif crt.Clipboard.Text.find("\n") > -1:
        vLines = crt.Clipboard.Text.split("\n")
    else:
        vLines = crt.Clipboard.Text.split("\r")


    # The number of "command columns" (nCmdCols) available is the
    # number of available screen columns minus the width of the
    # current shell prompt (minus one because the screen is not
    # zero-based).
    nCmdCols = crt.Screen.Columns - (crt.Screen.CurrentColumn - 1)
    nLineNumber = 0
    for strLine in vLines:
        # Send the next line to the remote
        crt.Screen.Send(strLine.strip("\r\n") + "\r")

        bSuccess = False

        # Determine if the script should wait for the full line to be
        # echo'd back by the remote all at once, or if the text of the
        # line should be detected character-by-character (which would
        # be the only way if the line is longer than the available # of
        # columns and would cause the line to wrap).
        if len(strLine) > nCmdCols:
            # Wait for each character (from the line of text just sent)
            # to be echo'd back to SecureCRT...
            for nCharIndex in range(1, len(strLine) + 1):
                strCharToWaitFor = strLine[nCharIndex-1:nCharIndex]
                Debug(
                    u"Waiting for {} (char #{} on line {}) to arrive...".format(
                    strCharToWaitFor, nCharIndex, nLineNumber + 1))
                bSuccess = crt.Screen.WaitForString(strCharToWaitFor, 3)
                Debug("")
                if not bSuccess:
                    break
        else:
            # If the current line isn't empty, wait for it to be echo'd back to us
            if not strLine.strip() == "":
                # Wait for the remote to echo the line back to SecureCRT; bail if
                # the remote fails to echo the line back to us within 3 seconds.
                Debug("Waiting for line #{} to arrive...".format(
                    nLineNumber +1))
                bSuccess = crt.Screen.WaitForString(strLine, 3)
                Debug("")
            else:
                Debug("Sent a blank line; waiting for CRLF")
                bSuccess = crt.Screen.WaitForString("\r\n")
                Debug("")

        if not bSuccess:
            Debug(
                "Sent %d lines, but the most recent line sent " % (nLineNumber + 1) +
                "was not echoed back to SecureCRT within 3 seconds.\r\n\r\n" +
                "Abandoning paste operation.")
            return

        nLineNumber += 1
          
    # Calculate seconds elapsed
    nTimeElapsed = time.time() - nStartTime
   
    # Inform that the data has all been sent.
    crt.Dialog.MessageBox(
        "%d lines from the clipboard have been sent.\r\n\r\n" % (nLineNumber) +
        "Time elapsed: %2.3f seconds." % (nTimeElapsed))

main()