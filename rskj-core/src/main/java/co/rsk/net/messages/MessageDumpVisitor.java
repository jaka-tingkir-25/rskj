/*
 * This file is part of RskJ
 * Copyright (C) 2019 RSK Labs Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package co.rsk.net.messages;

import co.rsk.config.RskSystemProperties;
import co.rsk.crypto.Keccak256;
import co.rsk.net.*;
import co.rsk.scoring.EventType;
import co.rsk.scoring.PeerScoringManager;
import co.rsk.validators.BlockValidationRule;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.core.Block;
import org.ethereum.core.BlockIdentifier;
import org.ethereum.core.Transaction;
import org.ethereum.net.p2p.Peer;
import org.ethereum.net.server.ChannelManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.*;
import java.util.stream.Collectors;

/**
 * The MessageVisitor handles the received wire messages resolution.
 * <p>
 * It should only visit a message once per instantiation.
 */
public class MessageDumpVisitor implements MessageVisitor<String> {

    private final MessageChannel sender;

    public MessageDumpVisitor(MessageChannel sender) {
        this.sender = sender;
    }


    @Override
    public String apply(BlockMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[BlockHash: %s]", message.getBlock().getHash()));
        sb.append(String.format("[Number: %d]", message.getBlock().getNumber()));
        sb.append(String.format("[TxCount: %s]", message.getBlock().getTransactionsList().size()));
        sb.append(String.format("[UnclesCount: %s]", message.getBlock().getUncleList().size()));

        return sb.toString();
    }


    @Override
    public String apply(StatusMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[BestBlockHash: %s]", Hex.toHexString(message.getStatus().getBestBlockHash())));
        sb.append(String.format("[BestBlockNumber: %d]", message.getStatus().getBestBlockNumber()));
        if (message.getStatus().getTotalDifficulty() != null) {
            sb.append(String.format("[Difficulty: %d]", message.getStatus().getTotalDifficulty().asBigInteger()));
        }
        return sb.toString();
    }

    @Override
    public String apply(GetBlockMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[BlockHash: %s]", Hex.toHexString(message.getBlockHash())));
        return sb.toString();
    }

    @Override
    public String apply(BlockRequestMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[RequestedBlockHash: %s]", Hex.toHexString(message.getBlockHash())));
        return sb.toString();
    }

    @Override
    public String apply(BlockResponseMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[BlockHash: %s]", message.getBlock().getHash()));
        sb.append(String.format("[Number: %d]", message.getBlock().getNumber()));
        sb.append(String.format("[TxCount: %s]", message.getBlock().getTransactionsList().size()));
        sb.append(String.format("[UnclesCount: %s]", message.getBlock().getUncleList().size()));
        return sb.toString();
    }

    @Override
    public String apply(SkeletonRequestMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[StartNumber: %d]", message.getStartNumber()));
        return sb.toString();
    }

    @Override
    public String apply(BlockHeadersRequestMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[RequestHash: %s]", Hex.toHexString(message.getHash())));
        sb.append(String.format("[RequestCount: %d]", message.getCount()));
        return sb.toString();
    }

    @Override
    public String apply(BlockHashRequestMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[RequestHeight: %s]", message.getHeight()));
        return sb.toString();
    }

    @Override
    public String apply(BlockHashResponseMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[BlockHash: %s]", Hex.toHexString(message.getHash())));
        return sb.toString();
    }

    @Override
    public String apply(NewBlockHashMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[BlockHash: %s]", Hex.toHexString(message.getBlockHash())));
        return sb.toString();
    }

    @Override
    public String apply(SkeletonResponseMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[IdentifiersCount: %d]", message.getBlockIdentifiers().size()));
        return sb.toString();
    }

    @Override
    public String apply(BlockHeadersResponseMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[HeadersCount: %d]", message.getBlockHeaders().size()));
        return sb.toString();
    }

    @Override
    public String apply(BodyRequestMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[BlockHash: %s]", Hex.toHexString(message.getBlockHash())));
        return sb.toString();
    }

    @Override
    public String apply(BodyResponseMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[TxCount: %d]", message.getTransactions().size()));
        sb.append(String.format("[UnclesCount: %d]", message.getUncles().size()));
        return sb.toString();
    }

    @Override
    public String apply(NewBlockHashesMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[IdentifiersCount: %d]", message.getBlockIdentifiers().size()));
        StringBuilder identifiers = new StringBuilder();
        message.getBlockIdentifiers().forEach(bi -> {
            identifiers.append(String.format("[BlockHash: %s]", Hex.toHexString(bi.getHash())));
            identifiers.append(String.format("[BlockNumber: %d]", bi.getNumber()));
        });
        sb.append("[").append(identifiers).append("]");
        return sb.toString();
    }

    @Override
    public String apply(TransactionsMessage message) {
        StringBuilder sb = new StringBuilder(basicInformation(message));
        sb.append(String.format("[TxCount: %d]", message.getTransactions().size()));
        return sb.toString();
    }

    private String basicInformation(Message message) {
        int hash = Arrays.hashCode(message.getEncoded());
        int size = message.getEncoded().length;
        return String.format("[Peer: %s][Address: %s][MessageType: %s][Hash: %d][Size (bytes): %d]",
                sender.getPeerNodeID(),
                sender.getAddress().toString(),
                message.getMessageType(),
                hash,
                size);
    }
}
