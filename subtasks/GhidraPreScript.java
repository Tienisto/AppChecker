//TODO write a description for this script
//@author 
//@category
//@keybinding 
//@menupath 
//@toolbar world.png

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import org.apache.commons.collections4.map.HashedMap;

import generic.json.JSONParser;
import generic.json.JSONToken;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class GhidraPreScript extends GhidraScript {

    // this script deactivates all analysis options which do not analyse strings
    // and activates all scripts which analyse strings

    public void run() throws Exception {
        Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String key : options.keySet()) {
            if(!key.toLowerCase().contains("string") && options.get(key).equals("true"))
                setAnalysisOption(currentProgram, key, "false");

            if(key.toLowerCase().contains("string") && options.get(key).equals("false"))
                setAnalysisOption(currentProgram, key, "true");
        }
    }

}