package bobcvesearch.core;

import bobcvesearch.model.NvdModel;
import bobcvesearch.model.NvdModel.CveItem;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.store.MMapDirectory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static bobcvesearch.BobPlugin.DB_LOCATION;
import static org.apache.lucene.document.Field.Store.YES;

public enum SearchIndex {;

    public static IndexWriter newIndexWriter(final String name) throws IOException {
        final var pathToIndex = Files.createDirectories(Paths.get(DB_LOCATION, "index", name));
        return new IndexWriter(new MMapDirectory(pathToIndex), new IndexWriterConfig(new StandardAnalyzer()));
    }

    public static IndexSearcher newIndexSearcher(final String name) throws IOException {
        final var pathToIndex = Files.createDirectories(Paths.get(DB_LOCATION, "index", name));
        return new IndexSearcher(DirectoryReader.open(new MMapDirectory(pathToIndex)));
    }

    public static void recreateIndex(final IndexWriter index, final NvdModel data) throws IOException {
        index.deleteAll();
        for (final var cve : data.CVE_Items) {
            for (final var cpe : cve.getCPEs()) {
                index.addDocument(newCveDocumentWithCPE(cve, cpe));
            }
            index.addDocument(newCveDocumentWithDescription(cve, cve.getDescription()));
        }
    }

    private static Document newCveDocumentWithCPE(final CveItem cve, final String cpe) {
        final var document = newCveDocument(cve);
        document.add(new StringField("cpe", cpe, YES));
        return document;
    }

    private static Document newCveDocumentWithDescription(final CveItem cve, final String description) {
        final var document = newCveDocument(cve);
        document.add(new TextField("description", description, YES));
        return document;
    }

    private static Document newCveDocument(final CveItem cve){
        final var document = new Document();
        document.add(new StringField("cve", cve.getID(), YES));
        document.add(new StringField("cvssV2", cve.getCvssV2(), YES));
        document.add(new StringField("cvssV3", cve.getCvssV3(), YES));
        return document;
    }

}
