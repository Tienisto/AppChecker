//TODO write a description for this script
//@author 
//@category Analysis->APK
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

public class GhidraAPKScript extends GhidraScript {

    Listing listing;

    public void run() throws Exception {

        String[] args = getScriptArgs();
        boolean deep = Boolean.valueOf(args[0]);
        String trackerPath = args[1];
        String csvPath = args[2];

        String pathJSON = new File(trackerPath).getAbsolutePath().replace("\\", "/");
        println("Path to tracker.json: " + pathJSON);

        String pathOutput = new File(csvPath).getAbsolutePath().replace("\\", "/");
        println("Path to output.csv: " + pathOutput);

        listing = currentProgram.getListing();
        monitor.setMessage("Looking for Strings...");

        // Parse json to List<JSONToken>
        List<JSONToken> tokens = new ArrayList<>();
        JSONParser parser = new JSONParser();
        String json = readFile(pathJSON);
        char[] jsonChars = json.toCharArray();
        parser.parse(jsonChars, tokens);

        // convert List<JSONToken> to List<Tracker>
        List<Tracker> trackers = getTrackers(tokens, json);

        // search for strings and match
        Map<Tracker, String> foundTrackers = new HashedMap<>();
        DataIterator dataIterator = listing.getDefinedData(true);
        while (dataIterator.hasNext() && !monitor.isCancelled()) {
            Data nextData = dataIterator.next();
            String type = nextData.getDataType().getName().toLowerCase();

            String string;
            if(deep) {
                string = listing.getDataAt(nextData.getMinAddress()).getLabel();
                if (string == null || (!type.contains("unicode") && !type.contains("string")))
                    continue;
            } else {
                string = String.valueOf(listing.getDataAt(nextData.getMinAddress()).getValue());
            }

            // check if string matches a network signature
            for(Tracker t : trackers) {
                if(t.matches(string)) {
                    foundTrackers.put(t, string);
                    break;
                }
            }
        }

        popup("Number of Strings found: " + foundTrackers.size());
        for (Entry<Tracker, String> entry : foundTrackers.entrySet()) {
            println(entry.getKey() + " -> "+ entry.getValue());
        }

        File csvOutputFile = new File(pathOutput);
        try (PrintWriter pw = new PrintWriter(csvOutputFile)) {
            for (Entry<Tracker, String> entry : foundTrackers.entrySet()) {
                Tracker t = entry.getKey();
                String trigger = "found network signature: \""+entry.getValue().replace(","," ").replace("\n", " ").replace("\r", " ")+"\"";
                pw.println(t.getWebsite().replace(","," ")+","+t.getCodeSignature().replace(","," ")+","+t.getNetworkSignature().replace(","," ")+","+t.getName().replace(","," ")+","+trigger);
            }
        }

        println("Script FINISH");
    }
    
    private String readFile(String path) throws IOException {
        File file = new File(path);

        BufferedReader br = new BufferedReader(new FileReader(file));
        StringBuilder builder = new StringBuilder();
        String curr;

        while ((curr = br.readLine()) != null) {
            builder.append(curr);
        }

        br.close();
        return builder.toString();
    }
    
    private List<Tracker> getTrackers(List<JSONToken> tokens, String json) {

        List<Tracker> trackers = new ArrayList<Tracker>();

        String website = null;
        String name = null;
        String networkSignature = null;
        String codeSignature = null;
        int counter = 0;
        for(JSONToken token : tokens) {

            if(counter == 0 || counter == 1 || counter == 2) {
                counter++;
                continue;
            }

            String s = json.substring(token.start, token.end);
            switch((counter-3) % 9) {
            case 2:
                name = s;
                break;
            case 4:
                codeSignature = s;
                break;
            case 6:
                networkSignature = s;
                break;
            case 8:
                website = s;
                break;
            }

            if(website != null && networkSignature != null && name != null) {
                // merge all 3 infos to an object
                trackers.add(new Tracker(website, networkSignature.replace("*", "").replace("\\", "").replace(".", "\\."), codeSignature, name));
                website = null;
                networkSignature = null;
                name = null;
            }

            counter++;
        }

        return trackers;
    }
    
    class Tracker {

        private final String website;
        private final String networkSignature;
        private final String codeSignature;
        private final String name;

        private final Pattern regexPattern;

        Tracker(String website, String networkSignature, String codeSignature, String name) {
            this.website = website;
            this.networkSignature = networkSignature;
            this.codeSignature = codeSignature;
            this.name = name;
            this.regexPattern = networkSignature.trim().isEmpty() || networkSignature.equals("NC") ? null : Pattern.compile(networkSignature);
        }

        public String getWebsite() {
            return website;
        }

        public String getNetworkSignature() {
            return networkSignature;
        }

        public String getCodeSignature() {
            return codeSignature;
        }

        public String getName() {
            return name;
        }

        public boolean matches(String s) {
            if(regexPattern == null)
                return false;
            return regexPattern.matcher(s).find();
        }

        @Override
        public String toString() {
            return "["+name+"] "+networkSignature;
        }
    }

}