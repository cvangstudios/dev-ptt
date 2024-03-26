# $language = "Python3"
# $interface = "1.0"

# SendASCIIWithEchoFlowControl.py
#
# Last Modified:
#   19 Apr, 2023:
#       - Updated to support either python v2 or v3
#       - Updated to support UTF-8 encoding
#       - Add ability to turn on verbose reporting as the
#         script is running.
#
#   29 May, 2020:
#     - Updated code to detect lines longer than the column screen width
#       of SecureCRT's terminal window, and wait for each character of
#       those lines to be echo'd back -- otherwise, the line  will be
#       wrapped when it's echo'd and WaitForString won't be able to find
#       it (it'll be echo'd back with CR and LF chars somewhere in the
#       midst of the line, which aren't there in the original line of
#       text).
#
# Description:
#   Demonstrates how to send text from a file to a remote device with "echo
#   flow control" enabled.  Echo Flow Control is where we wait for each line
#   to be echoed back by the remote host before the next line is sent.
#   This is one approach that attempts to prevent overwhelming a remote host
#   that cannot accept data as fast as SecureCRT normally sends it by making
#   sure the remote machine has received line before sending any subsequent
#   lines.

import SecureCRT
import time
import os

g_objTab = crt.GetScriptTab()
g_objTab.Screen.Synchronous = True
g_objTab.Screen.IgnoreEscape = True

g_strASCIIFile = ""
if crt.Arguments.Count > 0:
    strArgText = ""
    for strArg in crt.Arguments:
        if strArgText == "":
            strArgText = strArg
        else:
            strArgText = "{} {}".format(strArgText, strArg)
    g_strASCIIFile = strArgText

g_bDebug = False

def Debug(strMsg):
    global g_bDebug, g_objTab
    if g_bDebug:
        g_objTab.Session.SetStatusText(strMsg)

def main():
    global g_strASCIIFile, g_objTab
    
    # If there isn't an active connection, there's no point in continuing
    # since we can't send data.
    if not g_objTab.Session.Connected:
        crt.Dialog.MessageBox("Sending data requires an active connection.")
        return

    strHomeFolder = os.path.expanduser("~")
    if g_strASCIIFile != "":
        strSrcFile = g_strASCIIFile
        strSrcFile = strSrcFile.replace("~/", strHomeFolder + "/")
        if not os.path.isfile(strSrcFile):
            crt.Dialog.MessageBox(
                "File supplied as argument was not found:\r\n\r\n{}".format(
                    strSrcFile))
            strSrcFile = ""
    
    if strSrcFile == "":
        # Prompt the user to specify the file that contains the text to be sent
        # to the remote device.
        strSrcFile = crt.Dialog.FileOpenDialog(
            "Specify file containing text to send to the remote system",
            "Send Text",
            strHomeFolder + "/NameOfASCIIFileToSend.txt",
            "Text Files (*.txt)|*.txt||")

    # Bail if the user cancelled the open file dialog above
    if strSrcFile.strip() == "":
        return

    # Keep timing information so that we can display how long it took for the
    # data to be sent to the remote (each line sent only after the prior line
    # was echo'd back to SecureCRT, as a flow control mechanism).
    nStartTime = time.time()

    # open the text file and send it to the remote line by line
    import codecs
    fhDataFile = codecs.open(strSrcFile, "r", "utf-8")
    nLineNumber = 0
    for strLine in fhDataFile:
        strLine = strLine.replace("\r", "")
        strLine = strLine.replace("\n", "")
        
        # In case the file we loaded has a BOM (Byte Order Marker), let's
        # eliminate that from what we'll be sending/waiting-to-be-echo'd
        if nLineNumber == 0:
            strLine = strLine.replace(chr(65279), "")

        Debug("Sending line #{}".format(nLineNumber + 1))
        # Send the current line to the remote
        g_objTab.Screen.Send(strLine + "\r")

        bSuccess = False

        # Determine if the script should wait for the full line to be
        # echo'd back by the remote all at once, or if the text of the
        # line should be detected character-by-character (which would
        # be the only way if the line is longer than the available # of
        # columns and would cause the line to wrap).
        if len(strLine) > g_objTab.Screen.Columns:
            # Wait for each character (from the line of text just sent)
            # to be echo'd back to SecureCRT...
            strCharsFound = u""
            for nCharIndex in range(1, len(strLine) + 1):
                strCharToWaitFor = strLine[nCharIndex-1:nCharIndex]
                Debug(u"Line {} - Waiting for char #{}/{} ({})to echo...".format(
                    nLineNumber + 1, nCharIndex, len(strLine), ord(strCharToWaitFor)))
                bSuccess = g_objTab.Screen.WaitForString(strCharToWaitFor, 3)
                strCharsFound += strCharToWaitFor
                if not bSuccess:
                    break
        else:
            # If the current line isn't empty, wait for it to be echo'd back to us
            if not strLine == "":
                # Wait for the remote to echo the line back to SecureCRT; bail if
                # the remote fails to echo the line back to us within 3 seconds.
                Debug("Waiting for line #{} (normal) to echo...".format(
                    nLineNumber + 1))
                bSuccess = g_objTab.Screen.WaitForString(strLine, 3)
            else:
                Debug("Sent a blank line; waiting for CRLF")
                bSuccess = g_objTab.Screen.WaitForString("\r\n")
                Debug("")

        if not bSuccess:
            crt.Dialog.MessageBox(
                "Sent %d lines, but the most recent one was " % (nLineNumber + 1) +
                "was not echoed back to SecureCRT within 3 seconds.\r\n\r\n" +
                "Abandoning send ASCII operation.")
            return

        nLineNumber += 1

    fhDataFile.close()

    # Calculate seconds elapsed
    nTimeElapsed = time.time() - nStartTime

    # Inform that the data has all been sent.
    crt.Dialog.MessageBox(
        "Text in file '%s' (%d lines) " % (strSrcFile, nLineNumber) +
        "was sent to the remote.\r\n\r\n" +
        "Time elapsed: %1.3f seconds." % (nTimeElapsed))

    g_objTab.Session.SetStatusText("")

main()