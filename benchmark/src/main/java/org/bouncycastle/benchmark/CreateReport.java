package org.bouncycastle.benchmark;

import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeMap;
import java.util.stream.Collectors;


public class CreateReport
{
    public static void main(String[] args)
            throws Exception
    {

        if (args.length < 2)
        {
            System.err.println(" \"CHART TITLE\" <output html>  <csv file>  <csv file> ... <csv file>");
            System.exit(1);
        }

        TreeMap<String, List<Benchmark.Sample>> samples = new TreeMap<>();

        String title = args[0];

        String output = args[1];

        for (int t = 2; t < args.length; t++)
        {
            String arg = args[t];
            File f = new File(arg);
            if (!f.exists() || !f.isFile())
            {
                System.err.println("File " + f + " does not exist or is not a file");
                System.exit(1);
            }

            String fprefix;
            String suffux = "";

            if (f.getName().contains("JCE"))
            {
                suffux = "_JCE";
            }
            else
            {
                suffux = "_LOW";
            }

            if (f.getName().contains("Java"))
            {
                fprefix = "Java" + suffux;
            }
            else if (f.getName().contains("Native"))
            {
                fprefix = "Native" + suffux;
            }
            else
            {
                fprefix = f.getName();
            }


            //
            // Read data file and expand it into columns.
            //
            List<Benchmark.Sample> datum = readCSV(f);
            for (Benchmark.Sample data : datum)
            {
                String key = fprefix + "-" + data.label;
                if (!samples.containsKey(key))
                {
                    samples.put(key, new ArrayList<>());
                }
                List<Benchmark.Sample> column = samples.get(key);
                column.add(data);
            }
        }


        //
        // Make the blob of js that is the data.
        //


        ArrayList<String> keys = new ArrayList<String>(samples.keySet());
        Collections.sort(keys);

        //
        // Expand into columns
        //

        int max = Integer.MAX_VALUE;
        for (String key : keys)
        {
            List<Benchmark.Sample> sampleList = samples.get(key);
            max = Math.min(sampleList.size(), max);
        }

        StringBuilder jsonDataArray = new StringBuilder();
//        jsonDataArray.append("[");
//
//        for (int t = 0; t < max; t++) {
//            {
//
//                if (t > 0) {
//                    jsonDataArray.append(',');
//                }
//
//
//                jsonDataArray.append("[");
//                boolean first = false;
//                for (String key : keys) {
//                    List<Benchmark.Sample> sampleList = samples.get(key);
//                    Benchmark.Sample sample = sampleList.get(t);
//                    if (!first) {
//                        first = true;
//                        jsonDataArray.append(sample.messageSize);
//                        jsonDataArray.append(',');
//                    } else {
//                        jsonDataArray.append(',');
//                    }
//                    jsonDataArray.append(String.format("%.2f", sample.value));
//                }
//                jsonDataArray.append(']');
//            }
//        }
//
//        jsonDataArray.append("];");


        //
        // Generate column definitions.
        //
        StringBuilder columDefs = new StringBuilder();
        columDefs.append("[");
        for (int t = 0; t < keys.size(); t++)
        {
            if (t > 0)
            {
                columDefs.append(",");
            }
            columDefs.append(String.format("{selected: %b, label:\"%s\"}", t == 0, keys.get(t)));
        }
        columDefs.append("]");


        StringBuilder columnData = new StringBuilder();
        columnData.append("{");

        //
        // Encode X axis points
        //

        columnData.append("'X':");
        {
            //
            // Add X axis to data set
            //
            List<Benchmark.Sample> sampleList = samples.get(keys.get(0));
            columnData.append("[");
            columnData.append(sampleList.stream().map(it -> String.format("%d", it.messageSize)).collect(Collectors.joining(",")));
            columnData.append("],");

        }

        for (String key : keys)
        {
            List<Benchmark.Sample> sampleList = samples.get(key);
            columnData.append("'" + key + "':");
            columnData.append("[");
            columnData.append(sampleList.stream().map(it -> String.format("%.2f", it.value)).collect(Collectors.joining(",")));
            columnData.append("],");
        }
        columnData.append("}");


        StringBuilder dataChunk = new StringBuilder();
        dataChunk.append("var cols = ");
        dataChunk.append(columDefs);
        dataChunk.append(";\n");

        dataChunk.append("var colData = ");
        dataChunk.append(columnData);
        dataChunk.append(";\n");


        InputStream src = CreateReport.class.getResourceAsStream("/report.html");
        String template = new String(Streams.readAll(src));

        String report = template.replace("/* DATA */", dataChunk);

        report = report.replace("--title--", title);


        FileWriter fw = new FileWriter(new File(args[1]));
        fw.write(report);
        fw.flush();
        fw.close();

    }

    private static List<Benchmark.Sample> readCSV(File f)
            throws Exception
    {
        BufferedReader bin = new BufferedReader(new FileReader(f));

        String line = bin.readLine(); // throw away header
        ArrayList<Benchmark.Sample> out = new ArrayList<>();
        while ((line = bin.readLine()) != null)
        {
            out.add(new Benchmark.Sample(line));
        }
        bin.close();
        return out;
    }


}
