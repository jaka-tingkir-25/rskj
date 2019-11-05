package co.rsk;

import co.rsk.config.RskSystemProperties;
import co.rsk.core.TransactionExecutorFactory;
import co.rsk.core.bc.BlockExecutor;
import co.rsk.db.RepositoryLocator;
import co.rsk.db.StateRootHandler;
import co.rsk.trie.TrieStore;
import co.rsk.trie.TrieStoreImpl;
import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import org.ethereum.core.Block;
import org.ethereum.core.BlockHeader;
import org.ethereum.datasource.DataSourceWithCache;
import org.ethereum.datasource.KeyValueDataSource;
import org.ethereum.vm.trace.ProgramTraceProcessor;

public class ExecutionScopeFactory {

    private final RskSystemProperties rskSystemProperties;
    private final KeyValueDataSource dataSource;
    private final StateRootHandler stateRootHandler;
    private final TransactionExecutorFactory transactionExecutorFactory;

    public ExecutionScopeFactory(
            RskSystemProperties rskSystemProperties,
            KeyValueDataSource dataSource,
            StateRootHandler stateRootHandler,
            TransactionExecutorFactory transactionExecutorFactory) {

        this.rskSystemProperties = rskSystemProperties;
        this.dataSource = dataSource;
        this.stateRootHandler = stateRootHandler;
        this.transactionExecutorFactory = transactionExecutorFactory;
    }

    public ExecutionScope newScope(int statesCacheSize) {

        KeyValueDataSource ds = dataSource;
        if (rskSystemProperties.getStatesCacheSize() >= 0) {
            ds = new DataSourceWithCache(dataSource, statesCacheSize);
        }

        TrieStore trieStore = new TrieStoreImpl(ds);
        RepositoryLocator locator = new RepositoryLocator(trieStore, stateRootHandler);

        return new ExecutionScope(
                new BlockExecutor(
                        rskSystemProperties.getActivationConfig(),
                        locator,
                        stateRootHandler,
                        transactionExecutorFactory),
                trieStore);
    }

    public class ExecutionScope {

        private final BlockExecutor executor;
        private final TrieStore trieStore;

        private ExecutionScope(BlockExecutor executor, TrieStore trieStore) {
            this.executor = executor;
            this.trieStore = trieStore;
        }

        public void traceBlock(ProgramTraceProcessor programTraceProcessor, int vmTraceOptions, Block block, BlockHeader parent) {
            this.executor.traceBlock(
                    programTraceProcessor,
                    vmTraceOptions,
                    block,
                    parent,
                    false,
                    false);
        }

        public void flush() {
            trieStore.flush();
        }
    }
}
